package controller

import (
	"testing"
)

func TestControllerTargetCanonicalization(t *testing.T) {
	for _, host := range []string{"Example.TEST.", "example.test..", "127.0.0.1", "2001:0db8::1", "::ffff:192.0.2.1", "fe80::1%CaseSensitive", "123.example.test", "123."} {
		x := target
		x.Host = host
		a, err := normalize(x)
		if err != nil {
			t.Fatalf("%q: %v", host, err)
		}
		b, err := normalize(a)
		if err != nil || a != b {
			t.Fatalf("not canonical %q: %+v -> %+v (%v)", host, a, b, err)
		}
	}
	x := target
	x.Host = "fe80::1%bad\nzone"
	if _, err := normalize(x); err == nil {
		t.Fatal("accepted control in IPv6 zone")
	}
}

// Normalized identities must survive snapshot round trips unchanged.
func FuzzControllerTarget(f *testing.F) {
	for _, s := range []string{"example.test", "EXAMPLE.TEST..", "::1", "fe80::1%eth0", "127.0.0.1", "foo\nbar", "https://example.test"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, host string) {
		if len(host) > 1024 {
			return
		}
		x := target
		x.Host = host
		a, err := normalize(x)
		if err != nil {
			return
		}
		b, err := normalize(a)
		if err != nil || a != b {
			t.Fatalf("not idempotent: %#v -> %#v (%v)", a, b, err)
		}
	})
}
