package desync

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// decoyFor builds the decoy of opts for the ClientHello rec.
func decoyFor(t *testing.T, fake FakeOptions, rec []byte) []byte {
	t.Helper()
	if err := fake.validateDecoy(); err != nil {
		t.Fatal(err)
	}
	var frame helloFrame
	if rec != nil {
		var s helloScanner
		var err error
		if frame, err = s.scan(rec, (*ClientHelloOptions)(nil).limits()); err != nil {
			t.Fatal(err)
		}
	}
	c := &Conn{opts: Options{Fake: &fake}}
	decoy, err := c.fakeDecoy(rec, frame)
	if err != nil {
		t.Fatal(err)
	}
	return decoy
}

func TestFakeSNITemplate(t *testing.T) {
	for _, name := range []string{"a.b", "www.example.com", strings.Repeat("x", 63) + "." + strings.Repeat("y", 63) + "." + strings.Repeat("z", 60) + ".com"} {
		decoy := decoyFor(t, FakeOptions{TTL: 4, SNI: []string{name}}, nil)
		h, err := ParseHello(decoy)
		if err != nil || h.SNI != name {
			t.Fatalf("%s: %+v %v", name, h, err)
		}
		if len(name) <= 17+172 && len(decoy) != 517 {
			t.Fatalf("%s: the padding did not absorb the change: %d bytes", name, len(decoy))
		}
		// The rest of the template is kept.
		orig, _ := decodeHello(defaultFakeTLS())
		got, err := decodeHello(decoy)
		if err != nil || len(got.exts) != len(orig.exts) || got.random != orig.random || !bytes.Equal(got.suites, orig.suites) {
			t.Fatalf("%s: template changed beyond the SNI: %v", name, err)
		}
	}
	if defaultFakeTLS()[0] != 0x16 || mustParse(t, defaultFakeTLS()).SNI != "www.wikipedia.org" {
		t.Fatal("template was modified")
	}
}

func TestFakeSNIListAndWildcards(t *testing.T) {
	names := []string{"one.example", "two.example", "three.example"}
	seen := map[string]bool{}
	for i := 0; i < 200 && len(seen) < len(names); i++ {
		h := mustParse(t, decoyFor(t, FakeOptions{TTL: 4, SNI: names}, nil))
		seen[h.SNI] = true
	}
	for _, n := range names {
		if !seen[n] {
			t.Fatalf("name %s never drawn: %v", n, seen)
		}
	}
	for i := 0; i < 50; i++ {
		sni := mustParse(t, decoyFor(t, FakeOptions{TTL: 4, SNI: []string{"w*?#.example"}}, nil)).SNI
		if len(sni) != len("w*?#.example") || !strings.HasSuffix(sni, ".example") || sni[0] != 'w' {
			t.Fatalf("expanded %q", sni)
		}
		a, l, d := sni[1], sni[2], sni[3]
		if !(a >= 'a' && a <= 'z' || a >= '0' && a <= '9') || !(l >= 'a' && l <= 'z') || !(d >= '0' && d <= '9') {
			t.Fatalf("wildcards expanded to %q", sni)
		}
	}
}

func TestFakeFromOriginal(t *testing.T) {
	rec := captureHello(t, "real.example")
	orig, err := decodeHello(rec)
	if err != nil {
		t.Fatal(err)
	}
	// Input split into several records parses as one hello again.
	for _, input := range [][]byte{rec, reframeInput(rec, 7, 100)} {
		decoy := decoyFor(t, FakeOptions{TTL: 4, FromOriginal: true, SNI: []string{"decoy.example.org"}}, input)
		h := mustParse(t, decoy)
		if h.SNI != "decoy.example.org" {
			t.Fatalf("SNI %q", h.SNI)
		}
		got, err := decodeHello(decoy)
		if err != nil || len(got.exts) != len(orig.exts) || got.random != orig.random || !bytes.Equal(got.sessionID, orig.sessionID) {
			t.Fatalf("decoy differs from the original beyond the SNI: %v", err)
		}
		if len(decoy) != len(rec)+len("decoy.example.org")-len("real.example") {
			t.Fatalf("decoy has %d bytes, original %d", len(decoy), len(rec))
		}
	}
	// Without SNI the name is missing; the decoy gets one.
	noSNI := framingHello("x", 0)
	h, _ := decodeHello(noSNI)
	h.exts = nil
	h.hasExts = false
	plain := h.wire()
	if hello := mustParse(t, plain); hello.SNIOffset >= 0 {
		t.Fatal("fixture has an SNI")
	}
	if got := mustParse(t, decoyFor(t, FakeOptions{TTL: 4, FromOriginal: true, SNI: []string{"added.example"}}, plain)); got.SNI != "added.example" {
		t.Fatalf("added SNI %q", got.SNI)
	}
}

func TestFakeRandomize(t *testing.T) {
	orig, _ := decodeHello(defaultFakeTLS())
	a, err := decodeHello(decoyFor(t, FakeOptions{TTL: 4, Randomize: true}, nil))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := decodeHello(decoyFor(t, FakeOptions{TTL: 4, Randomize: true}, nil))
	if a.random == orig.random || a.random == b.random || bytes.Equal(a.sessionID, orig.sessionID) || len(a.sessionID) != len(orig.sessionID) {
		t.Fatal("random or session ID not randomized")
	}
	ks := a.exts[a.ext(extKeyShare)].data
	if bytes.Equal(ks, orig.exts[orig.ext(extKeyShare)].data) || !bytes.Equal(ks[:6], orig.exts[orig.ext(extKeyShare)].data[:6]) {
		t.Fatal("key share not randomized, or its framing changed")
	}
	if mustParse(t, a.wire()).SNI != "www.wikipedia.org" {
		t.Fatal("randomize changed the SNI")
	}
}

func TestFakeCustomPayloadSNI(t *testing.T) {
	payload := captureHello(t, "payload.example")
	h := mustParse(t, decoyFor(t, FakeOptions{TTL: 4, Payload: payload, SNI: []string{"other.example"}}, nil))
	if h.SNI != "other.example" {
		t.Fatalf("SNI %q", h.SNI)
	}
	if err := (&FakeOptions{TTL: 4, Payload: []byte("GET / HTTP/1.1\r\n\r\n"), SNI: []string{"a.example"}}).validateDecoy(); err == nil {
		t.Fatal("SNI accepted for a payload that is not a ClientHello")
	}
	// Without decoy options a payload is used as given.
	if !bytes.Equal(decoyFor(t, FakeOptions{TTL: 4, Payload: []byte("raw")}, nil), []byte("raw")) {
		t.Fatal("plain payload changed")
	}
}

func TestFakeDecoyValidation(t *testing.T) {
	for _, good := range []string{"a", "www.example.com", "xn--80ak6aa92e.com", "*.?#.example", "A-1.b"} {
		if err := validFakeSNI(good); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
	for _, bad := range []string{"", "-a.com", "a-.com", "a..b", ".a", "a.", "1.2.3.4", "::1", "a_b.com", "ex ample.com", "a,b", "a|b", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 127) + "aa"} {
		if err := validFakeSNI(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for name, f := range map[string]FakeOptions{
		"orig alone":        {TTL: 4, FromOriginal: true},
		"orig with payload": {TTL: 4, FromOriginal: true, Randomize: true, Payload: []byte{1}},
		"negative offset":   {TTL: 4, Offset: -1},
		"huge offset":       {TTL: 4, Offset: maxFakeOffset},
		"bad name":          {TTL: 4, SNI: []string{"ok.example", "bad_name"}},
		"too many names":    {TTL: 4, SNI: make([]string, maxFakeSNI+1)},
	} {
		f := f
		if err := (Options{Fake: &f}).Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	err := (Options{Fake: &FakeOptions{TTL: 4, SNI: []string{"ok.example"}, Randomize: true, FromOriginal: true, Offset: 3}}).Validate()
	if SupportsFake() && err != nil || !SupportsFake() && !errors.Is(err, ErrFakeUnsupported) {
		t.Fatalf("valid decoy options: %v", err)
	}
}

func TestFakeDecoyKey(t *testing.T) {
	base := Options{Fake: &FakeOptions{TTL: 4}}
	const want = "desync/v1;tlsrec=;split=;delay=0;hello=default;fake=ttl:4,prefix:0,timeout:0,payload:default;random=off"
	if got := base.Key(); got != want {
		t.Fatalf("key of options without decoy options changed:\n%s\n%s", got, want)
	}
	keys := map[string]bool{}
	for _, f := range []FakeOptions{
		{TTL: 4},
		{TTL: 4, SNI: []string{"a.example"}},
		{TTL: 4, SNI: []string{"b.example"}},
		{TTL: 4, SNI: []string{"a.example", "b.example"}},
		{TTL: 4, Randomize: true},
		{TTL: 4, FromOriginal: true, Randomize: true},
		{TTL: 4, Offset: 2},
	} {
		f := f
		keys[Options{Fake: &f}.Key()] = true
	}
	if len(keys) != 7 {
		t.Fatalf("decoy options are not all part of the key: %v", keys)
	}
}

func TestFakeBytesOffset(t *testing.T) {
	if got := fakeBytes([]byte("abcdef"), 2, 3); string(got) != "cde" {
		t.Fatalf("%q", got)
	}
	if got := fakeBytes([]byte("abc"), 2, 3); !bytes.Equal(got, []byte{'c', 0, 0}) {
		t.Fatalf("%q", got)
	}
	if got := fakeBytes([]byte("abc"), 9, 2); !bytes.Equal(got, []byte{0, 0}) {
		t.Fatalf("%q", got)
	}
}
