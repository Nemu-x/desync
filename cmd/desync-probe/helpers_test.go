package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The certificate of httptest servers is valid for example.com, 127.0.0.1
// and ::1, so example.com is the name every loopback test verifies.
const goodHost = "example.com"

type tlsFixture struct {
	srv   *httptest.Server
	port  int
	roots *x509.CertPool
}

func newTLSFixture(t *testing.T, h2 bool) *tlsFixture {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			http.Error(w, "HEAD only", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.EnableHTTP2 = h2
	srv.Config.ErrorLog = discardLogger()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return &tlsFixture{srv: srv, port: srv.Listener.Addr().(*net.TCPAddr).Port, roots: roots}
}

// loopbackProber resolves every name to 127.0.0.1 and trusts roots.
func loopbackProber(roots *x509.CertPool, timeout time.Duration) *prober {
	return &prober{
		lookup: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.IPv4(127, 0, 0, 1)}, nil
		},
		roots:     roots,
		timeout:   timeout,
		userAgent: "desync-probe-test",
	}
}

// rawServer accepts TCP connections and hands each to handle.
func rawServer(t *testing.T, handle func(net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			wg.Add(1)
			go func() { defer wg.Done(); handle(c) }()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return ln.Addr().(*net.TCPAddr).Port
}

// resetAfterHello reads the start of the ClientHello and answers with a
// TCP reset, as a filter that tears down a matching connection does.
func resetAfterHello(c net.Conn) {
	buf := make([]byte, 4096)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Read(buf)
	abort(c)
}

func abort(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	c.Close()
}

// silent reads everything and never answers, as a filter that drops a
// matching connection does.
func silent(c net.Conn) {
	_, _ = io.Copy(io.Discard, c)
}

// closeAfterHello reads the ClientHello and closes normally (FIN).
func closeAfterHello(c net.Conn) {
	buf := make([]byte, 4096)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Read(buf)
	c.Close()
}

// dpiProxy emulates a filter that inspects only the first segment it reads:
// when that segment contains the server name in one piece, it resets the
// connection; otherwise it forwards the connection to backend.
func dpiProxy(t *testing.T, sni string, backend int) int {
	return rawServer(t, func(c net.Conn) {
		buf := make([]byte, 16384)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			c.Close()
			return
		}
		_ = c.SetReadDeadline(time.Time{})
		if bytes.Contains(buf[:n], []byte(sni)) {
			abort(c)
			return
		}
		up, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(backend)))
		if err != nil {
			c.Close()
			return
		}
		defer up.Close()
		defer c.Close()
		if _, err := up.Write(buf[:n]); err != nil {
			return
		}
		go func() { _, _ = io.Copy(up, c); up.Close() }()
		_, _ = io.Copy(c, up)
	})
}

// tlsSilentServer completes TLS with the fixture's certificate, then never
// answers the HTTP request.
func tlsSilentServer(t *testing.T, f *tlsFixture) int {
	cfg := &tls.Config{Certificates: f.srv.TLS.Certificates}
	return rawServer(t, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
		if tc.Handshake() == nil {
			_, _ = io.Copy(io.Discard, tc)
		}
		tc.Close()
	})
}

// countingDialer records the largest number of connections open at once.
type countingDialer struct {
	open, peak, dials int64
}

func (d *countingDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	atomic.AddInt64(&d.dials, 1)
	n := atomic.AddInt64(&d.open, 1)
	for {
		p := atomic.LoadInt64(&d.peak)
		if n <= p || atomic.CompareAndSwapInt64(&d.peak, p, n) {
			break
		}
	}
	return &countedConn{TCPConn: c.(*net.TCPConn), d: d}, nil
}

// countedConn keeps *net.TCPConn embedded so desync still finds the socket.
type countedConn struct {
	*net.TCPConn
	d    *countingDialer
	once sync.Once
}

func (c *countedConn) NetConn() net.Conn { return c.TCPConn }

func (c *countedConn) Close() error {
	c.once.Do(func() { atomic.AddInt64(&c.d.open, -1) })
	return c.TCPConn.Close()
}

func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }
