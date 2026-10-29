package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Nemu-x/desync"
	"github.com/Nemu-x/desync/controller"
)

// Error classes recorded for a failed attempt.
const (
	classTimeout     = "timeout"
	classReset       = "reset"
	classEOF         = "eof"
	classCert        = "cert"
	classRefused     = "refused"
	classUnreachable = "unreachable"
	classTLSAlert    = "tls-alert"
	classLocal       = "local" // the library rejected or could not apply the strategy
	classCanceled    = "canceled"
	classOther       = "other"
)

// Attempt stages: where an attempt stopped.
const (
	stageDial = "dial"
	stageTLS  = "tls"
	stageHTTP = "http"
	stageDone = "done"
)

// prober runs one measurement: dial, wrap with desync, verified TLS handshake
// and one HEAD request. It is safe for concurrent use.
type prober struct {
	// lookup resolves a name; nil uses the system resolver.
	lookup func(ctx context.Context, host string) ([]net.IP, error)
	// dial opens the TCP connection; nil uses net.Dialer.
	dial func(ctx context.Context, network, address string) (net.Conn, error)
	// roots verifies server certificates; nil uses the system roots.
	roots *x509.CertPool
	// timeout bounds a single attempt (and a single DNS lookup).
	timeout   time.Duration
	userAgent string

	mu  sync.Mutex
	dns map[string]*dnsEntry
}

type dnsEntry struct {
	once sync.Once
	res  dnsResult
}

type dnsResult struct {
	IPs      []net.IP
	Err      error
	Duration time.Duration
}

// resolve looks host up once; later calls return the same answer, so every
// strategy is measured against the same server address.
func (p *prober) resolve(ctx context.Context, host string) dnsResult {
	p.mu.Lock()
	if p.dns == nil {
		p.dns = map[string]*dnsEntry{}
	}
	e := p.dns[host]
	if e == nil {
		e = &dnsEntry{}
		p.dns[host] = e
	}
	p.mu.Unlock()
	e.once.Do(func() {
		if ip := net.ParseIP(host); ip != nil {
			e.res = dnsResult{IPs: []net.IP{ip}}
			return
		}
		ctx, cancel := context.WithTimeout(ctx, p.timeout)
		defer cancel()
		start := time.Now()
		lookup := p.lookup
		if lookup == nil {
			lookup = systemLookup
		}
		ips, err := lookup(ctx, host)
		e.res = dnsResult{IPs: ips, Err: err, Duration: time.Since(start)}
		if err == nil && len(ips) == 0 {
			e.res.Err = errors.New("no addresses")
		}
	})
	return e.res
}

var resolver = net.DefaultResolver

func systemLookup(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

// pickAddress chooses the address every strategy is measured against: the
// first IPv4 answer, otherwise the first answer.
func pickAddress(ips []net.IP) net.IP {
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip
		}
	}
	if len(ips) > 0 {
		return ips[0]
	}
	return nil
}

// attemptResult is one measurement of one strategy against one target.
type attemptResult struct {
	Stage      string // where it stopped; stageDone on success
	Class      string // error class, empty on success
	Err        error
	Status     int
	Proto      string
	TLSVersion string
	Dial       time.Duration
	TLS        time.Duration
	FirstByte  time.Duration
}

func (a attemptResult) ok() bool { return a.Stage == stageDone }

// attempt measures opts against host at ip:port.
func (p *prober) attempt(ctx context.Context, host string, ip net.IP, port int, opts desync.Options) attemptResult {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	fail := func(r attemptResult, stage string, err error) attemptResult {
		r.Stage, r.Err, r.Class = stage, err, classify(err)
		return r
	}
	var r attemptResult
	if err := opts.Validate(); err != nil {
		return fail(r, stageDial, err)
	}
	dial := p.dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	start := time.Now()
	raw, err := dial(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	r.Dial = time.Since(start)
	if err != nil {
		return fail(r, stageDial, err)
	}
	defer raw.Close()

	cfg := &tls.Config{
		ServerName: host,
		RootCAs:    p.roots,
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	}
	conn := tls.Client(desync.WrapConn(raw, opts), cfg)
	defer conn.Close()
	start = time.Now()
	err = conn.HandshakeContext(ctx)
	r.TLS = time.Since(start)
	if err != nil {
		return fail(r, stageTLS, err)
	}
	state := conn.ConnectionState()
	r.TLSVersion = tlsVersionName(state.Version)

	// The transport takes over the connection that was already measured; a
	// second dial would be a different measurement and is refused.
	var once sync.Once
	transport := &http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			var c net.Conn
			once.Do(func() { c = conn })
			if c == nil {
				return nil, errors.New("desync-probe: one connection per attempt")
			}
			return c, nil
		},
		ForceAttemptHTTP2: true,
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	u := url.URL{Scheme: "https", Host: host, Path: "/"}
	if port != 443 {
		u.Host = net.JoinHostPort(host, strconv.Itoa(port))
	}
	var firstByte time.Duration
	start = time.Now()
	trace := &httptrace.ClientTrace{GotFirstResponseByte: func() { firstByte = time.Since(start) }}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodHead, u.String(), nil)
	if err != nil {
		return fail(r, stageHTTP, err)
	}
	req.Header.Set("User-Agent", p.userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return fail(r, stageHTTP, err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	r.FirstByte = firstByte
	if r.FirstByte == 0 {
		r.FirstByte = time.Since(start)
	}
	r.Stage, r.Status, r.Proto = stageDone, resp.StatusCode, resp.Proto
	return r
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

// classify maps an error to a coarse class that is comparable across
// operating systems and languages of system error messages.
func classify(err error) string {
	if err == nil {
		return ""
	}
	for _, local := range []error{
		desync.ErrFakeUnsupported, desync.ErrFakeRequiresTCP, desync.ErrFakeBusy,
		desync.ErrSplitWaitUnsupported, desync.ErrSplitWaitRequiresTCP, desync.ErrSplitWaitTimeout,
		desync.ErrDisorderUnsupported, desync.ErrOOBUnsupported, desync.ErrSocketMethodRequiresTCP,
	} {
		if errors.Is(err, local) {
			return classLocal
		}
	}
	if strings.HasPrefix(err.Error(), "desync:") {
		return classLocal
	}
	if errors.Is(err, context.Canceled) {
		return classCanceled
	}
	var verr *tls.CertificateVerificationError
	var uerr x509.UnknownAuthorityError
	var herr x509.HostnameError
	var ierr x509.CertificateInvalidError
	var rerr x509.SystemRootsError
	if errors.As(err, &verr) || errors.As(err, &uerr) || errors.As(err, &herr) || errors.As(err, &ierr) || errors.As(err, &rerr) {
		return classCert
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch {
		case errnoIn(errno, resetErrnos):
			return classReset
		case errnoIn(errno, refusedErrnos):
			return classRefused
		case errnoIn(errno, unreachableErrnos):
			return classUnreachable
		case errnoIn(errno, timeoutErrnos):
			return classTimeout
		}
	}
	var nerr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &nerr) && nerr.Timeout()) {
		return classTimeout
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return classEOF
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "remote error: tls:"):
		return classTLSAlert
	case strings.Contains(msg, "connection reset") || strings.Contains(msg, "forcibly closed") || strings.Contains(msg, "broken pipe"):
		return classReset
	case strings.Contains(msg, "server closed") || strings.Contains(msg, "unexpected eof"):
		return classEOF
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded"):
		return classTimeout
	}
	return classOther
}

func errnoIn(e syscall.Errno, set []syscall.Errno) bool {
	for _, v := range set {
		if e == v {
			return true
		}
	}
	return false
}

// strategyProber adapts the prober to the controller's Prober contract, so
// the same measurement can drive controller discovery: a probe succeeds with
// Application proof when a verified TLS peer answered the HEAD request.
type strategyProber struct {
	p       *prober
	catalog map[string]desync.Options
}

var _ controller.Prober = strategyProber{}

func (s strategyProber) Probe(ctx context.Context, t controller.Target, id string) (controller.Proof, error) {
	opts, ok := s.catalog[id]
	if !ok {
		return controller.Proof{}, fmt.Errorf("unknown strategy %q", id)
	}
	d := s.p.resolve(ctx, t.Host)
	if d.Err != nil {
		return controller.Proof{}, fmt.Errorf("resolve %s: %w", t.Host, d.Err)
	}
	r := s.p.attempt(ctx, t.Host, pickAddress(d.IPs), int(t.Port), opts)
	if !r.ok() {
		return controller.Proof{Level: proofLevel(r.Stage), Code: r.Class}, fmt.Errorf("%s: %s: %w", r.Stage, r.Class, r.Err)
	}
	return controller.Proof{Level: controller.Application, Code: "http-" + strconv.Itoa(r.Status)}, nil
}

// proofLevel reports what a failed attempt still verified.
func proofLevel(stage string) controller.Verification {
	switch stage {
	case stageTLS:
		return controller.TCP
	case stageHTTP:
		return controller.TLS
	}
	return controller.Unknown
}
