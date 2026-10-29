package main

import (
	"strings"
	"testing"

	"github.com/Nemu-x/desync"
)

func allCaps() desync.Capabilities {
	return desync.Capabilities{
		OS: "test", FakeTCP: true, FakeUDP: true, TTLControl: true, OOB: true,
		Disorder:    desync.DisorderCapability{Supported: true},
		Ack:         desync.AckCapability{Sent: true, Acked: true},
		Unsupported: map[string]string{},
	}
}

func names(ps []preset) map[string]bool {
	m := map[string]bool{}
	for _, p := range ps {
		m[p.Name] = true
	}
	return m
}

func TestCatalogFilteredByCapabilities(t *testing.T) {
	full := catalog()
	usable, skipped := buildCatalog(full, allCaps())
	if len(usable) != len(full) || len(skipped) != 0 {
		t.Fatalf("all capabilities: %d usable, %d skipped of %d", len(usable), len(skipped), len(full))
	}

	darwin := allCaps()
	darwin.OS = "darwin"
	darwin.FakeTCP = false
	darwin.Ack.Sent = false
	darwin.Unsupported["fake-tcp"] = "no splice"
	usable, skipped = buildCatalog(full, darwin)
	got := map[string]string{}
	for _, s := range skipped {
		got[s.Name] = s.Reason
		if s.Key == "" {
			t.Errorf("%s: skipped preset without key", s.Name)
		}
	}
	for _, n := range []string{"fake-ttl3", "fake-ttl5", "fake-ttl8"} {
		if got[n] != "fake-tcp: no splice" {
			t.Errorf("%s: reason %q", n, got[n])
		}
	}
	if !strings.Contains(got["split-1s-wait-sent"], "sent") || !strings.Contains(got["split-1s-wait-sent"], "darwin") {
		t.Errorf("wait-sent reason %q", got["split-1s-wait-sent"])
	}
	if len(skipped) != 4 {
		t.Errorf("darwin-like: skipped %v", got)
	}
	if u := names(usable); !u["split-1s-wait-acked"] || !u["disoob-1s"] || !u[baselineName] {
		t.Errorf("darwin-like: usable %v", u)
	}

	none := desync.Capabilities{OS: "plan9", Unsupported: map[string]string{"disorder": "not implemented on plan9"}}
	usable, skipped = buildCatalog(full, none)
	for _, p := range usable {
		if len(p.needs) != 0 {
			t.Errorf("no capabilities: kept %s", p.Name)
		}
	}
	for _, s := range skipped {
		if s.Reason == "" {
			t.Errorf("%s: empty reason", s.Name)
		}
		if strings.HasPrefix(s.Name, "disorder") && s.Reason != "disorder: not implemented on plan9" {
			t.Errorf("%s: reason %q", s.Name, s.Reason)
		}
	}
	if len(usable)+len(skipped) != len(full) {
		t.Fatalf("lost presets: %d + %d != %d", len(usable), len(skipped), len(full))
	}
}

// Every preset this platform keeps must also pass Options.Validate here.
func TestPlatformCatalogValidates(t *testing.T) {
	usable, _ := buildCatalog(catalog(), desync.PlatformCapabilities())
	if _, invalid := validateCatalog(usable); len(invalid) != 0 {
		t.Fatalf("presets kept by capabilities but rejected by Validate: %+v", invalid)
	}
	if usable[0].Name != baselineName || usable[0].Opts.Enabled() {
		t.Fatalf("first preset %q must be the untransformed baseline", usable[0].Name)
	}
}

func TestStableIDs(t *testing.T) {
	seenID, seenName := map[string]string{}, map[string]bool{}
	for _, p := range catalog() {
		id := p.ID()
		if len(id) != 11 || id[0] != 's' {
			t.Errorf("%s: malformed id %q", p.Name, id)
		}
		if other, dup := seenID[id]; dup {
			t.Errorf("%s and %s share id %s", p.Name, other, id)
		}
		if seenName[p.Name] || strings.ContainsAny(p.Name, ", ") {
			t.Errorf("bad or duplicate name %q", p.Name)
		}
		seenID[id], seenName[p.Name] = p.Name, true
		if p.ID() != strategyID(p.Opts) {
			t.Errorf("%s: id not derived from the key", p.Name)
		}
	}
	// IDs are part of the report format; they change only when Key changes.
	golden := map[string]string{baselineName: "s21c85503c1", "tlsrec-1s": "s30879a4293", "split-1s": "saac5e9ce30", "fake-ttl5": "s62607cf66f"}
	for _, p := range catalog() {
		if want, ok := golden[p.Name]; ok && p.ID() != want {
			t.Errorf("%s: id %s, want %s (key %q)", p.Name, p.ID(), want, p.Opts.Key())
		}
	}
	a := desync.Options{TLSRec: posList("1+s")}
	b := desync.Options{TLSRec: posList("1+s")}
	if strategyID(a) != strategyID(b) || strategyID(a) == strategyID(desync.Options{TLSRec: posList("2+s")}) {
		t.Fatal("ids must follow the options")
	}
}

func TestSelectPresets(t *testing.T) {
	all := catalog()
	got, err := selectPresets(all, "split-1s, tlsrec-1s")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Name != baselineName {
		t.Fatalf("got %v", names(got))
	}
	if _, err := selectPresets(all, "tlsrec-1s,nope"); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("unknown preset: %v", err)
	}
	if got, _ := selectPresets(all, "all"); len(got) != len(all) {
		t.Fatal("all must keep everything")
	}
}

func TestCustomPreset(t *testing.T) {
	c := customFlags{name: "mine", tlsrec: "1+s,3+s", split: "1", wait: "none", oobByte: "a", ttl: 4}
	if !c.set() {
		t.Fatal("custom flags not detected")
	}
	p, err := c.preset()
	if err != nil {
		t.Fatal(err)
	}
	want := desync.Options{TLSRec: posList("1+s", "3+s"), Split: posList("1")}
	if p.Opts.Key() != want.Key() || p.Name != "mine" {
		t.Fatalf("key %q, want %q", p.Opts.Key(), want.Key())
	}
	ps, err := addCustom(catalog(), p)
	if err != nil || len(ps) != len(catalog())+1 {
		t.Fatalf("addCustom: %v, %d", err, len(ps))
	}
	// The same options as a preset add nothing.
	same := customFlags{name: "x", tlsrec: "1+s", wait: "none", oobByte: "a"}
	sp, _ := same.preset()
	if ps, _ := addCustom(catalog(), sp); len(ps) != len(catalog()) {
		t.Fatal("duplicate strategy added twice")
	}
	if _, err := addCustom(catalog(), preset{Name: "tlsrec-1s", Opts: desync.Options{Split: posList("7")}}); err == nil {
		t.Fatal("name clash accepted")
	}
	if _, err := (customFlags{disorder: true, wait: "none", oobByte: "a"}).preset(); err == nil {
		t.Fatal("disorder without split accepted")
	}
	if _, err := (customFlags{split: "x", wait: "none"}).preset(); err == nil {
		t.Fatal("bad position accepted")
	}
	if (customFlags{wait: "none", oobByte: "a", ttl: 4}).set() {
		t.Fatal("defaults count as a custom strategy")
	}
	if b, err := parseByte("0x41"); err != nil || b != 'A' {
		t.Fatalf("parseByte: %v %v", b, err)
	}
	if _, err := parseByte("0x1g"); err == nil {
		t.Fatal("bad hex accepted")
	}
}

func TestParseTargets(t *testing.T) {
	got, err := parseTargets("# comment\nYouTube.com\nhttps://discord.com/, x.com:8443 x.com\n\n  ya.ru  # control\n", 443)
	if err != nil {
		t.Fatal(err)
	}
	want := []target{{"youtube.com", 443}, {"discord.com", 443}, {"x.com", 8443}, {"x.com", 443}, {"ya.ru", 443}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: %v, want %v", i, got[i], want[i])
		}
	}
	for _, bad := range []string{"a.com:0", "a.com:x", "user@a.com"} {
		if _, err := parseTargets(bad, 443); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	def, err := parseTargets(defaultTargets, 443)
	if err != nil || len(def) < 10 {
		t.Fatalf("default list: %v, %d", err, len(def))
	}
	if !names2(def)["ya.ru"] || !names2(def)["example.com"] {
		t.Fatal("default list lacks the control sites")
	}
}

func names2(ts []target) map[string]bool {
	m := map[string]bool{}
	for _, t := range ts {
		m[t.Host] = true
	}
	return m
}
