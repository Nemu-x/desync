package desync

import (
	"bytes"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestEstimateHops(t *testing.T) {
	for _, tc := range []struct {
		ttl, hops int
		ok        bool
	}{
		{64, 0, true}, {63, 1, true}, {60, 4, true}, {50, 14, true}, {33, 31, true},
		{128, 0, true}, {127, 1, true}, {120, 8, true}, {116, 12, true}, {97, 31, true},
		{255, 0, true}, {254, 1, true}, {243, 12, true}, {224, 31, true},
		{32, 0, false}, {1, 0, false}, {0, 0, false}, {-1, 0, false},
		{65, 0, false}, {96, 0, false}, {129, 0, false}, {200, 0, false}, {223, 0, false}, {256, 0, false},
	} {
		hops, ok := EstimateHops(tc.ttl)
		if hops != tc.hops || ok != tc.ok {
			t.Errorf("EstimateHops(%d) = %d, %v; want %d, %v", tc.ttl, hops, ok, tc.hops, tc.ok)
		}
	}
}

func TestAutoTTLPolicy(t *testing.T) {
	for _, tc := range []struct {
		policy    AutoTTL
		hops, ttl int
		ok        bool
	}{
		{AutoTTL{}, 10, 9, true},
		{AutoTTL{}, 4, 3, true},
		{AutoTTL{}, 3, 0, false}, // Min 3 would reach the server
		{AutoTTL{}, 0, 0, false},
		{AutoTTL{}, 30, 20, true}, // clamped to Max
		{AutoTTL{Delta: 1, Min: 3, Max: 20}, 12, 11, true},
		{AutoTTL{Delta: 2, Min: 1, Max: 255}, 5, 3, true},
		{AutoTTL{Delta: 2, Min: 1, Max: 255}, 2, 1, true}, // 0 raised to Min
		{AutoTTL{Delta: 2, Min: 1, Max: 255}, 1, 0, false},
		{AutoTTL{Delta: 3}, 5, 3, true}, // 2 raised to Min 3, still short
		{AutoTTL{Delta: 4, Min: 6, Max: 8}, 31, 8, true},
		{AutoTTL{Delta: 4, Min: 6, Max: 8}, 6, 0, false},
	} {
		if err := tc.policy.Validate(); err != nil {
			t.Fatalf("%+v: %v", tc.policy, err)
		}
		ttl, ok := tc.policy.TTL(tc.hops)
		if ttl != tc.ttl || ok != tc.ok {
			t.Errorf("%+v.TTL(%d) = %d, %v; want %d, %v", tc.policy, tc.hops, ttl, ok, tc.ttl, tc.ok)
		}
	}
}

func TestAutoTTLValidate(t *testing.T) {
	for _, bad := range []AutoTTL{
		{Delta: -1}, {Delta: 255}, {Min: -1}, {Min: 256}, {Max: -1}, {Max: 256},
		{Min: 30},        // above the default Max 20
		{Min: 9, Max: 8}, // inverted
		{Max: 2},         // below the default Min 3
		{Delta: 1000, Min: 1, Max: 2},
	} {
		err := bad.Validate()
		if err == nil || !strings.HasPrefix(err.Error(), "desync: ") {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	for _, good := range []AutoTTL{{}, {Delta: 254, Min: 255, Max: 255}, {Min: 30, Max: 40}, {Min: 1, Max: 2}} {
		if err := good.Validate(); err != nil {
			t.Errorf("%+v: %v", good, err)
		}
	}
}

func TestFakeAutoTTLValidation(t *testing.T) {
	for _, ttl := range []int{-1, 256} {
		err := (Options{Fake: &FakeOptions{TTL: ttl, AutoTTL: &AutoTTL{}}}).Validate()
		if err == nil || !strings.HasPrefix(err.Error(), "desync: ") {
			t.Fatalf("TTL %d with AutoTTL: %v", ttl, err)
		}
	}
	if err := (Options{Fake: &FakeOptions{AutoTTL: &AutoTTL{Min: 50}}}).Validate(); err == nil || !strings.Contains(err.Error(), "auto TTL") {
		t.Fatalf("invalid policy accepted: %v", err)
	}
	if err := (Options{Fake: &FakeOptions{}}).Validate(); err == nil || err.Error() != "desync: fake TTL must be between 1 and 255" {
		t.Fatalf("TTL 0 without AutoTTL: %v", err)
	}
	caps := validatedCapabilities()
	auto := (Options{Fake: &FakeOptions{AutoTTL: &AutoTTL{}}}).Validate()
	fallback := (Options{Fake: &FakeOptions{TTL: 6, AutoTTL: &AutoTTL{}}}).Validate()
	switch {
	case !caps.FakeTCP:
		if !errors.Is(auto, ErrFakeUnsupported) || !errors.Is(fallback, ErrFakeUnsupported) {
			t.Fatalf("%s: %v / %v", runtime.GOOS, auto, fallback)
		}
	case caps.AutoTTL.IPv4 || caps.AutoTTL.IPv6:
		if auto != nil || fallback != nil {
			t.Fatalf("%s: %v / %v", runtime.GOOS, auto, fallback)
		}
	default:
		if !errors.Is(auto, ErrAutoTTLUnsupported) || fallback != nil {
			t.Fatalf("%s: %v / %v", runtime.GOOS, auto, fallback)
		}
	}
}

func TestAutoTTLKey(t *testing.T) {
	fixed := Options{Fake: &FakeOptions{TTL: 4}}
	const want = "desync/v1;tlsrec=;split=;delay=0;hello=default;fake=ttl:4,prefix:0,timeout:0,payload:default;random=off"
	if got := fixed.Key(); got != want {
		t.Fatalf("fixed-TTL key changed:\n got %s\nwant %s", got, want)
	}
	auto := Options{Fake: &FakeOptions{AutoTTL: &AutoTTL{}}}
	const wantAuto = "desync/v1;tlsrec=;split=;delay=0;hello=default;fake=ttl:0,prefix:0,timeout:0,payload:default,auto:1:3-20;random=off"
	if got := auto.Key(); got != wantAuto {
		t.Fatalf("auto key:\n got %s\nwant %s", got, wantAuto)
	}
	explicit := Options{Fake: &FakeOptions{AutoTTL: &AutoTTL{Delta: 1, Min: 3, Max: 20}}}
	if explicit.Key() != auto.Key() {
		t.Fatal("defaults and explicit defaults differ")
	}
	keys := map[string]bool{}
	for _, o := range []Options{
		fixed, auto,
		{Fake: &FakeOptions{AutoTTL: &AutoTTL{Delta: 2}}},
		{Fake: &FakeOptions{AutoTTL: &AutoTTL{Min: 4}}},
		{Fake: &FakeOptions{AutoTTL: &AutoTTL{Max: 12}}},
		{Fake: &FakeOptions{TTL: 4, AutoTTL: &AutoTTL{}}},
	} {
		if keys[o.Key()] {
			t.Fatalf("duplicate key %s", o.Key())
		}
		keys[o.Key()] = true
	}
}

func TestAutoTTLCapabilityPerOS(t *testing.T) {
	c := PlatformCapabilities()
	var want AutoTTLCapability
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		want = AutoTTLCapability{Mechanism: "IPV6_RECVHOPLIMIT/IPV6_2292PKTOPTIONS", IPv6: true}
	}
	if c.AutoTTL != want {
		t.Fatalf("%s: auto TTL %+v, want %+v", runtime.GOOS, c.AutoTTL, want)
	}
	for name, missing := range map[string]bool{"auto-ttl-ipv4": !want.IPv4, "auto-ttl-ipv6": !want.IPv6} {
		if reason, ok := c.Unsupported[name]; ok != missing || ok && reason == "" {
			t.Fatalf("%s: reason %q (present %v), want present %v", name, reason, ok, missing)
		}
	}
	t.Logf("%s auto TTL: %+v, unsupported: ipv4 %q ipv6 %q", runtime.GOOS, c.AutoTTL, c.Unsupported["auto-ttl-ipv4"], c.Unsupported["auto-ttl-ipv6"])
}

// A connection whose family cannot be observed reports why, on every OS.
func TestObserveHopsUnobservableLoopback(t *testing.T) {
	caps := PlatformCapabilities().AutoTTL
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			client, _ := loopbackPair(t, network)
			_, err := ObserveHops(WrapConn(client, Options{TLSRec: []Pos{{Offset: 1}}}))
			supported := caps.IPv4 && network == "tcp4" || caps.IPv6 && network == "tcp6"
			// A supported family was not prepared with ControlAutoTTL.
			if supported && !errors.Is(err, ErrAutoTTLUnobserved) || !supported && !errors.Is(err, ErrAutoTTLUnsupported) {
				t.Fatalf("ObserveHops: %v", err)
			}
			t.Logf("%v", err)
		})
	}
}

// AutoTTL falls back to Fake.TTL when the path cannot be observed, and fails
// before sending anything without a fallback. tcp4 loopback is unobservable
// on every OS.
func TestFakeAutoTTLFallback(t *testing.T) {
	if !SupportsFake() {
		t.Skip("no TCP fake on " + runtime.GOOS)
	}
	hello := captureHello(t, "example.test")
	tail := []byte("after the hello")
	t.Run("fallback", func(t *testing.T) {
		client, server := loopbackPair(t, "tcp4")
		// Loopback delivers the first transmission: fake bytes equal to the
		// real ones keep the stream verifiable.
		w := WrapConn(client, Options{Fake: &FakeOptions{TTL: 64, AutoTTL: &AutoTTL{}, Payload: hello}}).(*Conn)
		if ttl, auto := w.FakeTTL(); ttl != 0 || auto {
			t.Fatalf("FakeTTL before the write: %d %v", ttl, auto)
		}
		_ = w.SetWriteDeadline(time.Now().Add(10 * time.Second))
		read := readUntil(server, tail)
		input := append(append([]byte(nil), hello...), tail...)
		if n, err := w.Write(input); err != nil || n != len(input) {
			t.Fatalf("Write: %d %v", n, err)
		}
		if got := <-read; !bytes.Equal(got, input) {
			t.Fatalf("server stream changed: %d bytes", len(got))
		}
		if ttl, auto := w.FakeTTL(); ttl != 64 || auto {
			t.Fatalf("FakeTTL: %d %v, want the fallback 64", ttl, auto)
		}
	})
	t.Run("no-fallback", func(t *testing.T) {
		opts := Options{Fake: &FakeOptions{AutoTTL: &AutoTTL{}}}
		if err := opts.Validate(); err != nil {
			t.Skipf("rejected by Validate: %v", err)
		}
		client, server := loopbackPair(t, "tcp4")
		w := WrapConn(client, opts)
		_ = w.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := w.Write(hello); !errors.Is(err, ErrAutoTTLUnsupported) {
			t.Fatalf("Write: %v", err)
		}
		_ = server.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if n, _ := server.Read(make([]byte, 1)); n != 0 {
			t.Fatal("bytes reached the server")
		}
	})
}
