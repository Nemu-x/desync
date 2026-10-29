package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Nemu-x/desync"
	"github.com/Nemu-x/desync/controller"
)

var loopback = net.IPv4(127, 0, 0, 1)

func platformPresets(t *testing.T) []preset {
	t.Helper()
	caps := desync.PlatformCapabilities()
	kept, _ := filterCatalog(caps)
	usable, skipped := availablePresets(caps)
	if len(usable) != len(kept) {
		t.Fatalf("invalid presets: %+v", skipped)
	}
	return usable
}

// isFake reports presets whose first transmission carries other bytes. On
// loopback no router drops the low-TTL transmission. On Windows the server
// then receives the fake bytes and cannot complete the handshake; on Linux
// the receiver reads the shared page after the wrapper rewrote it with the
// original bytes, so the handshake completes. Both are expected here.
func isFake(p preset) bool { return p.Options.Fake != nil }

func TestProbeEveryPresetOnLoopback(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		h2 := h2
		t.Run(fmt.Sprintf("h2=%v", h2), func(t *testing.T) {
			f := newTLSFixture(t, h2)
			p := loopbackProber(f.roots, 10*time.Second)
			for _, ps := range platformPresets(t) {
				p.timeout = 10 * time.Second
				if isFake(ps) {
					// The server waits for the rest of a ClientHello it cannot parse.
					p.timeout = time.Second
				}
				r := p.attempt(context.Background(), goodHost, loopback, f.port, ps.Options)
				if isFake(ps) {
					if r.Class == classLocal || (!r.ok() && r.Stage != stageTLS) {
						t.Errorf("%s: loopback fake gave stage=%s class=%s err=%v", ps.Name, r.Stage, r.Class, r.Err)
					}
					t.Logf("%s on loopback: stage=%s class=%s", ps.Name, r.Stage, r.Class)
					continue
				}
				if !r.ok() {
					t.Errorf("%s: stage=%s class=%s err=%v", ps.Name, r.Stage, r.Class, r.Err)
					continue
				}
				wantProto := "HTTP/1.1"
				if h2 {
					wantProto = "HTTP/2.0"
				}
				if r.Status != 204 || r.Proto != wantProto || r.TLSVersion == "" {
					t.Errorf("%s: status=%d proto=%s tls=%s", ps.Name, r.Status, r.Proto, r.TLSVersion)
				}
			}
		})
	}
}

func TestProbeErrorClasses(t *testing.T) {
	f := newTLSFixture(t, false)
	cases := []struct {
		name, host string
		port       int
		timeout    time.Duration
		stage      string
		class      string
	}{
		{"reset after ClientHello", goodHost, rawServer(t, resetAfterHello), 5 * time.Second, stageTLS, classReset},
		{"never answers", goodHost, rawServer(t, silent), 300 * time.Millisecond, stageTLS, classTimeout},
		{"closes after ClientHello", goodHost, rawServer(t, closeAfterHello), 5 * time.Second, stageTLS, classEOF},
		{"bad certificate", "wrong-name.test", f.port, 5 * time.Second, stageTLS, classCert},
		{"no HTTP answer", goodHost, tlsSilentServer(t, f), 500 * time.Millisecond, stageHTTP, classTimeout},
	}
	for _, c := range cases {
		for _, ps := range []preset{{Name: baselineName}, {Name: "tlsrec-1s", Options: desync.Options{TLSRec: posList("1+s")}}} {
			p := loopbackProber(f.roots, c.timeout)
			start := time.Now()
			r := p.attempt(context.Background(), c.host, loopback, c.port, ps.Options)
			if r.Stage != c.stage || r.Class != c.class {
				t.Errorf("%s/%s: stage=%s class=%s err=%v; want %s/%s", c.name, ps.Name, r.Stage, r.Class, r.Err, c.stage, c.class)
			}
			if el := time.Since(start); el > c.timeout+2*time.Second {
				t.Errorf("%s/%s: took %v with timeout %v", c.name, ps.Name, el, c.timeout)
			}
		}
	}
}

func TestProbeRefusedAndLocal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	p := loopbackProber(nil, 5*time.Second)
	if r := p.attempt(context.Background(), goodHost, loopback, port, desync.Options{}); r.Stage != stageDial || r.Class != classRefused {
		t.Errorf("closed port: stage=%s class=%s err=%v", r.Stage, r.Class, r.Err)
	}
	// A strategy the library rejects is recorded as local, before dialing.
	bad := desync.Options{Disorder: true}
	if r := p.attempt(context.Background(), goodHost, loopback, port, bad); r.Class != classLocal || r.Dial != 0 {
		t.Errorf("invalid options: class=%s dial=%v err=%v", r.Class, r.Dial, r.Err)
	}
}

func TestClassify(t *testing.T) {
	op := func(err error) error {
		return &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", err)}
	}
	cases := map[string]error{
		classReset:       op(resetErrnos[0]),
		classRefused:     op(refusedErrnos[0]),
		classUnreachable: op(unreachableErrnos[0]),
		classTimeout:     context.DeadlineExceeded,
		classEOF:         fmt.Errorf("wrapped: %w", io.ErrUnexpectedEOF),
		classTLSAlert:    errors.New("remote error: tls: handshake failure"),
		classLocal:       fmt.Errorf("x: %w", desync.ErrFakeUnsupported),
		classCanceled:    context.Canceled,
		classOther:       errors.New("something else"),
	}
	for want, err := range cases {
		if got := classify(err); got != want {
			t.Errorf("classify(%v) = %s, want %s", err, got, want)
		}
	}
	if classify(nil) != "" {
		t.Error("nil error classified")
	}
	if classify(op(syscall.Errno(99999))) != classOther {
		t.Error("unknown errno not other")
	}
}

func TestResolveOnce(t *testing.T) {
	calls := 0
	p := &prober{timeout: time.Second, lookup: func(context.Context, string) ([]net.IP, error) {
		calls++
		return []net.IP{net.ParseIP("2001:4860::1"), net.ParseIP("203.0.113.7")}, nil
	}}
	for i := 0; i < 3; i++ {
		d := p.resolve(context.Background(), "a.example")
		if d.Err != nil || pickAddress(d.IPs).String() != "203.0.113.7" {
			t.Fatalf("resolve: %+v", d)
		}
	}
	if calls != 1 {
		t.Fatalf("lookup called %d times", calls)
	}
	if d := p.resolve(context.Background(), "192.0.2.1"); d.Err != nil || calls != 1 {
		t.Fatal("an IP literal must not be looked up")
	}
	empty := &prober{timeout: time.Second, lookup: func(context.Context, string) ([]net.IP, error) { return nil, nil }}
	if d := empty.resolve(context.Background(), "x"); d.Err == nil {
		t.Fatal("empty answer accepted")
	}
}

// The probe satisfies the controller's Prober contract, so the same
// measurement can drive automatic discovery.
func TestControllerProberContract(t *testing.T) {
	f := newTLSFixture(t, true)
	p := loopbackProber(f.roots, 5*time.Second)
	cat := map[string]desync.Options{}
	var ids []string
	for _, ps := range platformPresets(t) {
		if isFake(ps) || ps.Name == baselineName {
			continue
		}
		cat[ps.ID()] = ps.Options
		ids = append(ids, ps.ID())
	}
	sp := strategyProber{p: p, catalog: cat}
	c, err := controller.New(controller.Config{Candidates: ids, PolicyVersion: "probe-test"}, sp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sel, err := c.Select(ctx, controller.Target{Network: "loopback", Host: goodHost, Port: uint16(f.port), ProbeID: "head-v1"}, controller.SelectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, known := cat[sel.Strategy]; !known || sel.Level != controller.Application || sel.Source != "probe" {
		t.Fatalf("selection %+v", sel)
	}

	proof, err := sp.Probe(ctx, controller.Target{Host: goodHost, Port: uint16(rawServer(t, resetAfterHello))}, ids[0])
	if err == nil || proof.Code != classReset || proof.Level != controller.TCP {
		t.Fatalf("blocked probe: %+v %v", proof, err)
	}
	if _, err := sp.Probe(ctx, controller.Target{Host: goodHost, Port: 1}, "unknown"); err == nil {
		t.Fatal("unknown strategy accepted")
	}
	if !strings.Contains(fmt.Sprint(sp.Probe(ctx, controller.Target{Host: goodHost, Port: uint16(f.port)}, ids[0])), "http-204") {
		t.Fatal("successful proof must carry the HTTP status")
	}
}

// On an OS without socket-dependent methods the loopback probe changes
// nothing; elsewhere it resolves them.
func TestPlatformCapabilitiesResolvesConditional(t *testing.T) {
	caps := platformCapabilities()
	if len(caps.Conditional) != 0 {
		t.Fatalf("unresolved: %v", caps.Conditional)
	}
	if plat := desync.PlatformCapabilities(); len(plat.Conditional) == 0 &&
		(caps.Ack != plat.Ack || caps.FakeTCP != plat.FakeTCP || caps.Disorder != plat.Disorder) {
		t.Fatalf("probed %+v, platform %+v", caps, plat)
	}
}
