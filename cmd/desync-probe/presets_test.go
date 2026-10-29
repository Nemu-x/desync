package main

import (
	"strings"
	"testing"

	"github.com/Nemu-x/desync"
	"github.com/Nemu-x/desync/presets"
)

func names(ps []preset) map[string]bool {
	m := map[string]bool{}
	for _, p := range ps {
		m[p.Name] = true
	}
	return m
}

func pos(s string) desync.Pos {
	p, err := desync.ParsePos(s)
	if err != nil {
		panic(err)
	}
	return p
}

func posList(ss ...string) []desync.Pos {
	out := make([]desync.Pos, len(ss))
	for i, s := range ss {
		out[i] = pos(s)
	}
	return out
}

// catalog is the shared TCP catalog, independent of the platform.
func catalog() []preset { return presets.TCP() }

// filterCatalog keeps the catalog entries caps provides, without Validate.
func filterCatalog(caps desync.Capabilities) ([]preset, []skippedPreset) {
	return presets.Filter(presets.TCP(), caps)
}

// The catalog moved to the presets package, which tests it per platform; the
// probe must still see every preset in the same order with the same IDs.
func TestProbeUsesSharedCatalog(t *testing.T) {
	caps := desync.PlatformCapabilities()
	usable, skipped := availablePresets(caps)
	want, wantSkipped := presets.Available(caps)
	if len(usable) != len(want) || len(skipped) != len(wantSkipped) || len(usable)+len(skipped) != len(catalog()) {
		t.Fatalf("%d usable, %d skipped of %d", len(usable), len(skipped), len(catalog()))
	}
	for i := range usable {
		if usable[i].Name != want[i].Name || usable[i].ID() != want[i].ID() {
			t.Fatalf("%d: %s, want %s", i, usable[i].Name, want[i].Name)
		}
	}
	if usable[0].Name != baselineName || usable[0].Options.Enabled() {
		t.Fatalf("first preset %q must be the untransformed baseline", usable[0].Name)
	}
	kept, _ := filterCatalog(caps)
	if len(kept) != len(usable) {
		t.Fatalf("presets kept by capabilities but rejected by Validate: %+v", skipped)
	}
}

func TestStableIDs(t *testing.T) {
	// IDs are part of the report format; they change only when Key changes.
	golden := map[string]string{baselineName: "s21c85503c1", "tlsrec-1s": "s30879a4293", "split-1s": "saac5e9ce30", "fake-ttl5": "s62607cf66f"}
	found := 0
	for _, p := range catalog() {
		if p.ID() != presets.OptionsID(p.Options) {
			t.Errorf("%s: id not derived from the key", p.Name)
		}
		if want, ok := golden[p.Name]; ok {
			found++
			if p.ID() != want {
				t.Errorf("%s: id %s, want %s (key %q)", p.Name, p.ID(), want, p.Key())
			}
		}
	}
	if found != len(golden) {
		t.Fatalf("%d of %d golden presets in the catalog", found, len(golden))
	}
	c, err := (customFlags{tlsrec: "1+s", wait: "none", oobByte: "a"}).preset()
	if err != nil || c.ID() != golden["tlsrec-1s"] {
		t.Fatalf("custom strategy id %s, %v", c.ID(), err)
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
	if p.Key() != want.Key() || p.Name != "mine" {
		t.Fatalf("key %q, want %q", p.Key(), want.Key())
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
	if _, err := addCustom(catalog(), preset{Name: "tlsrec-1s", Options: desync.Options{Split: posList("7")}}); err == nil {
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
