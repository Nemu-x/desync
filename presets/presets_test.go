package presets

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Nemu-x/desync"
	"github.com/Nemu-x/desync/controller"
)

// IDs are part of the desync-probe report format and of persisted settings;
// they change only when Options.Key changes. The first four were pinned by
// desync-probe before the catalog moved here.
var goldenTCP = []struct{ name, id string }{
	{"none", "s21c85503c1"},
	{"tlsrec-1s", "s30879a4293"},
	{"tlsrec-3s", "s15f5cfcd23"},
	{"tlsrec-before-sni", "s1855283037"},
	{"tlsrec-multi", "sf0976f29b4"},
	{"split-1", "se00f908f95"},
	{"split-1s", "saac5e9ce30"},
	{"tlsrec-1s-split-1", "se37a819919"},
	{"random-tlsrec", "s554e5bf206"},
	{"random-split", "s5642b6c74f"},
	{"disorder-1", "s49914f9987"},
	{"disorder-1s", "s03a1c27bb3"},
	{"oob-1", "s13ab09bb4d"},
	{"oob-1s", "scacee1fcd5"},
	{"disoob-1s", "s4797c0aa21"},
	{"split-1s-wait-sent", "s09fcfddf9c"},
	{"split-1s-wait-acked", "s30e9c34c4a"},
	{"fake-ttl3", "s9e8b15049f"},
	{"fake-ttl5", "s62607cf66f"},
	{"fake-ttl8", "sbdf889895a"},
	{"fake-ttl5-sni", "s6aafd402a0"},
	{"split-1s-fake-ttl5", "s6fae1e8a40"},
	{"disorder-1-fake-ttl5", "s63fc503aca"},
}

var goldenUDP = []struct{ name, id string }{
	{"udp-zero-ttl3", "u6ebe839e20"},
	{"udp-zero-ttl5", "ud13ae97453"},
	{"udp-zero-ttl8", "u8c9983f843"},
	{"udp-zero-ttl5-r2", "uebdba14699"},
	{"udp-zero-ttl5-r12", "ufe49f977b8"},
	{"udp-quic-ttl3", "ud88b8db473"},
	{"udp-quic-ttl5", "u9309af956b"},
	{"udp-quic-ttl8", "u127438077f"},
	{"udp-quic-ttl5-r2", "u044556c7c3"},
}

func TestGoldenIDsAndOrder(t *testing.T) {
	tcp := TCP()
	if len(tcp) != len(goldenTCP) {
		t.Fatalf("%d TCP presets, golden list has %d", len(tcp), len(goldenTCP))
	}
	for i, p := range tcp {
		if p.Name != goldenTCP[i].name || p.ID() != goldenTCP[i].id {
			t.Errorf("TCP %d: %s %s, want %s %s (key %q)", i, p.Name, p.ID(), goldenTCP[i].name, goldenTCP[i].id, p.Key())
		}
	}
	udp := UDP()
	if len(udp) != len(goldenUDP) {
		t.Fatalf("%d UDP presets, golden list has %d", len(udp), len(goldenUDP))
	}
	for i, p := range udp {
		if p.Name != goldenUDP[i].name || p.ID() != goldenUDP[i].id {
			t.Errorf("UDP %d: %s %s, want %s %s (key %q)", i, p.Name, p.ID(), goldenUDP[i].name, goldenUDP[i].id, p.Key())
		}
	}
}

func TestIDsDerivedAndUnique(t *testing.T) {
	ids, names := map[string]string{}, map[string]bool{}
	check := func(name, id, key, want string, needs []Feature, desc string) {
		if len(id) != 11 || !wellFormed(id) || id != want {
			t.Errorf("%s: id %q, want %q", name, id, want)
		}
		if other, dup := ids[id]; dup {
			t.Errorf("%s and %s share id %s", name, other, id)
		}
		if names[name] || name == "" || strings.ContainsAny(name, ", \t") {
			t.Errorf("bad or duplicate name %q", name)
		}
		if key == "" || desc == "" {
			t.Errorf("%s: empty key or description", name)
		}
		for _, f := range needs {
			if strings.HasPrefix(f.String(), "Feature(") {
				t.Errorf("%s: unknown feature %d", name, f)
			}
		}
		ids[id], names[name] = name, true
	}
	for _, p := range TCP() {
		check(p.Name, p.ID(), p.Key(), shortID('s', p.Options.Key()), p.Needs, p.Description)
		if p.ID()[0] != 's' {
			t.Errorf("%s: TCP id %s", p.Name, p.ID())
		}
	}
	for _, p := range UDP() {
		check(p.Name, p.ID(), p.Key(), shortID('u', p.Options.Key()), p.Needs, p.Description)
		if p.Options.Counters != nil {
			t.Errorf("%s: catalog counters", p.Name)
		}
	}
	a, b := desync.Options{TLSRec: posList("1+s")}, desync.Options{TLSRec: posList("1+s")}
	if OptionsID(a) != OptionsID(b) || OptionsID(a) == OptionsID(desync.Options{TLSRec: posList("2+s")}) {
		t.Fatal("ids must follow the options")
	}
	if UDPOptionsID(desync.UDPOptions{TTL: 5}) == UDPOptionsID(desync.UDPOptions{TTL: 5, Template: desync.UDPTemplateQUICInitial}) {
		t.Fatal("UDP template not part of the id")
	}
}

func TestCatalogIsACopy(t *testing.T) {
	a := TCP()
	a[1].Options.TLSRec[0] = pos("7")
	a[1].Name = "changed"
	if b := TCP(); b[1].Name != "tlsrec-1s" || b[1].ID() != "s30879a4293" {
		t.Fatal("TCP shares state between calls")
	}
	u := UDP()
	u[0].Options.TTL = 99
	if UDP()[0].Options.TTL != 3 {
		t.Fatal("UDP shares state between calls")
	}
}

func TestRanked(t *testing.T) {
	tcp := TCP()
	r := Ranked(tcp)
	if len(r) != len(tcp) || r[0].Name != BaselineName || r[0].Options.Enabled() {
		t.Fatalf("baseline must stay first: %s", r[0].Name)
	}
	for i := 1; i < len(r); i++ {
		if r[i-1].Rank > r[i].Rank {
			t.Fatalf("%s (rank %d) before %s (rank %d)", r[i-1].Name, r[i-1].Rank, r[i].Name, r[i].Rank)
		}
	}
	pos := map[string]int{}
	for i, p := range r {
		pos[p.Name] = i
	}
	// Ordering rationale: record split, write split, wait, disorder/OOB, fake, combinations.
	for _, pair := range [][2]string{
		{"tlsrec-multi", "random-tlsrec"}, // catalog order within a rank
		{"random-tlsrec", "split-1"},
		{"random-split", "split-1s-wait-sent"},
		{"split-1s-wait-acked", "disorder-1"},
		{"disoob-1s", "fake-ttl3"},
		{"split-1s-fake-ttl5", "disorder-1-fake-ttl5"},
	} {
		if pos[pair[0]] >= pos[pair[1]] {
			t.Errorf("%s must come before %s", pair[0], pair[1])
		}
	}
	if tcp[8].Name != "random-tlsrec" {
		t.Fatal("Ranked modified its input")
	}
	u := RankedUDP(UDP())
	if u[0].Name != "udp-zero-ttl5-r2" || u[1].Name != "udp-quic-ttl5-r2" || u[len(u)-1].Name != "udp-zero-ttl5-r12" {
		t.Fatalf("UDP rank order: %v", udpNames(u))
	}
}

// Capabilities as PlatformCapabilities reports them on each OS (see the
// *_windows.go, *_linux.go and *_darwin.go files of the root package).
func simulated(goos string) desync.Capabilities {
	c := desync.Capabilities{OS: goos, Unsupported: map[string]string{}}
	switch goos {
	case "windows":
		c.FakeTCP, c.FakeUDP, c.TTLControl, c.OOB = true, true, true, true
		c.Disorder = desync.DisorderCapability{Supported: true}
		c.Ack = desync.AckCapability{Sent: true, Acked: true}
	case "linux":
		c.FakeTCP, c.FakeUDP, c.TTLControl, c.OOB = true, true, true, true
		c.Disorder = desync.DisorderCapability{Supported: true}
		c.Ack = desync.AckCapability{Sent: true, Acked: true}
	case "darwin":
		c.FakeUDP, c.TTLControl, c.OOB = true, true, true
		c.Disorder = desync.DisorderCapability{Supported: true}
		c.Ack = desync.AckCapability{Acked: true}
		c.Unsupported["fake-tcp"] = "no splice"
	default:
		for _, k := range []string{"fake-tcp", "fake-udp", "disorder", "oob"} {
			c.Unsupported[k] = "not implemented on " + goos
		}
	}
	return c
}

func names(ps []Preset) []string {
	out := []string{}
	for _, p := range ps {
		out = append(out, p.Name)
	}
	return out
}

func udpNames(ps []UDPPreset) []string {
	out := []string{}
	for _, p := range ps {
		out = append(out, p.Name)
	}
	return out
}

func without(all []string, drop ...string) []string {
	skip := map[string]bool{}
	for _, d := range drop {
		skip[d] = true
	}
	out := []string{}
	for _, n := range all {
		if !skip[n] {
			out = append(out, n)
		}
	}
	return out
}

func TestFilterPerOS(t *testing.T) {
	all := names(TCP())
	allUDP := udpNames(UDP())
	fakes := []string{"fake-ttl3", "fake-ttl5", "fake-ttl8", "fake-ttl5-sni", "split-1s-fake-ttl5", "disorder-1-fake-ttl5"}
	cases := []struct {
		os           string
		tcp, udp     []string
		reasons      map[string]string
		reasonSubstr map[string][]string
	}{
		{os: "windows", tcp: all, udp: allUDP},
		{os: "linux", tcp: all, udp: allUDP},
		{os: "darwin", tcp: without(all, append([]string{"split-1s-wait-sent"}, fakes...)...), udp: allUDP,
			reasons:      map[string]string{"fake-ttl5": "fake-tcp: no splice", "disorder-1-fake-ttl5": "fake-tcp: no splice"},
			reasonSubstr: map[string][]string{"split-1s-wait-sent": {"sent", "darwin"}}},
		{os: "plan9",
			tcp: []string{"none", "tlsrec-1s", "tlsrec-3s", "tlsrec-before-sni", "tlsrec-multi", "split-1", "split-1s", "tlsrec-1s-split-1", "random-tlsrec", "random-split"},
			udp: []string{},
			reasons: map[string]string{"disorder-1": "disorder: not implemented on plan9", "oob-1": "oob: not implemented on plan9",
				"disoob-1s": "disorder: not implemented on plan9", "fake-ttl3": "fake-tcp: not implemented on plan9",
				"disorder-1-fake-ttl5": "disorder: not implemented on plan9", "udp-quic-ttl5": "fake-udp: not implemented on plan9"},
			reasonSubstr: map[string][]string{"split-1s-wait-acked": {"acked", "plan9"}}},
	}
	for _, c := range cases {
		caps := simulated(c.os)
		usable, skipped := Filter(TCP(), caps)
		usableUDP, skippedUDP := FilterUDP(UDP(), caps)
		if got := names(usable); !reflect.DeepEqual(got, c.tcp) {
			t.Errorf("%s: usable %v, want %v", c.os, got, c.tcp)
		}
		if got := udpNames(usableUDP); !reflect.DeepEqual(got, c.udp) {
			t.Errorf("%s: usable UDP %v, want %v", c.os, got, c.udp)
		}
		if len(usable)+len(skipped) != len(all) || len(usableUDP)+len(skippedUDP) != len(allUDP) {
			t.Errorf("%s: presets lost", c.os)
		}
		reason := map[string]string{}
		for _, s := range append(skipped, skippedUDP...) {
			if s.Reason == "" || s.Key == "" {
				t.Errorf("%s: %s skipped without key or reason", c.os, s.Name)
			}
			reason[s.Name] = s.Reason
		}
		for n, want := range c.reasons {
			if reason[n] != want {
				t.Errorf("%s: %s reason %q, want %q", c.os, n, reason[n], want)
			}
		}
		for n, subs := range c.reasonSubstr {
			for _, sub := range subs {
				if !strings.Contains(reason[n], sub) {
					t.Errorf("%s: %s reason %q lacks %q", c.os, n, reason[n], sub)
				}
			}
		}
		// Available adds the Validate check of the running system; on the
		// simulated OS of this system it must drop nothing more.
		avail, availSkipped := Available(caps)
		availUDP, _ := AvailableUDP(caps)
		if len(avail)+len(availSkipped) != len(all) {
			t.Errorf("%s: Available lost presets", c.os)
		}
		if c.os == runtime.GOOS {
			if !reflect.DeepEqual(names(avail), c.tcp) || !reflect.DeepEqual(udpNames(availUDP), c.udp) {
				t.Errorf("%s: Available %v / %v differs from Filter", c.os, names(avail), udpNames(availUDP))
			}
		}
		for _, p := range avail {
			if err := p.Options.Validate(); err != nil {
				t.Errorf("%s: Available kept %s: %v", c.os, p.Name, err)
			}
		}
	}
}

// The simulation above must match what this system really reports.
func TestSimulatedMatchesPlatform(t *testing.T) {
	switch runtime.GOOS {
	case "windows", "linux", "darwin":
	default:
		t.Skip("no simulation for " + runtime.GOOS)
	}
	real, sim := desync.PlatformCapabilities(), simulated(runtime.GOOS)
	for _, f := range []Feature{FeatureDisorder, FeatureOOB, FeatureFakeTCP, FeatureSplitWaitSent, FeatureSplitWaitAcked, FeatureFakeUDP} {
		a, _ := f.Check(real)
		b, _ := f.Check(sim)
		if a != b {
			t.Errorf("%s: platform %v, simulation %v", f, a, b)
		}
	}
}

// Every preset this platform keeps must also pass Validate here.
func TestPlatformCatalogValidates(t *testing.T) {
	caps := desync.PlatformCapabilities()
	kept, _ := Filter(TCP(), caps)
	usable, skipped := Available(caps)
	if len(usable) != len(kept) {
		t.Fatalf("presets kept by capabilities but rejected by Validate: %+v", skipped)
	}
	for _, p := range usable {
		if err := p.Options.Validate(); err != nil {
			t.Errorf("%s: %v", p.Name, err)
		}
	}
	if usable[0].Name != BaselineName || usable[0].Options.Enabled() {
		t.Fatalf("first preset %q must be the untransformed baseline", usable[0].Name)
	}
	keptUDP, _ := FilterUDP(UDP(), caps)
	usableUDP, skippedUDP := AvailableUDP(caps)
	if len(usableUDP) != len(keptUDP) {
		t.Fatalf("UDP presets kept by capabilities but rejected by Validate: %+v", skippedUDP)
	}
	for _, p := range usableUDP {
		if err := p.Options.Validate(); err != nil {
			t.Errorf("%s: %v", p.Name, err)
		}
	}
	if caps.FakeUDP != (len(usableUDP) == len(UDP())) {
		t.Errorf("FakeUDP %v but %d of %d UDP presets usable", caps.FakeUDP, len(usableUDP), len(UDP()))
	}
}

func TestByID(t *testing.T) {
	for _, p := range TCP() {
		m, ok := ByID(p.ID())
		if !ok || m.TCP == nil || m.UDP != nil || m.TCP.Name != p.Name || m.TCP.Key() != p.Key() {
			t.Errorf("%s: ByID(%s) = %+v, %v", p.Name, p.ID(), m, ok)
		}
	}
	for _, p := range UDP() {
		m, ok := ByID(p.ID())
		if !ok || m.UDP == nil || m.TCP != nil || m.UDP.Name != p.Name || m.UDP.Key() != p.Key() {
			t.Errorf("%s: ByID(%s) = %+v, %v", p.Name, p.ID(), m, ok)
		}
	}
	for _, id := range []string{"", "s", "s0000000000", "u0000000000", "x30879a4293", "S30879a4293", "s30879a42931", "u30879a4293"} {
		if _, ok := ByID(id); ok {
			t.Errorf("ByID(%q) found", id)
		}
	}
	m, _ := ByID("s30879a4293")
	m.TCP.Options.TLSRec[0] = pos("9")
	if m2, _ := ByID("s30879a4293"); m2.TCP.Options.TLSRec[0].String() != "1+s" {
		t.Fatal("ByID returned shared state")
	}
}

func TestIDJSON(t *testing.T) {
	type settings struct {
		TCP   ID   `json:"tcp"`
		UDP   ID   `json:"udp,omitempty"`
		Tried []ID `json:"tried"`
	}
	in := settings{TCP: ID(TCP()[1].ID()), UDP: ID(UDP()[0].ID()), Tried: []ID{"s21c85503c1", "s62607cf66f"}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"tcp":"s30879a4293","udp":"u6ebe839e20","tried":["s21c85503c1","s62607cf66f"]}` {
		t.Fatalf("json %s", b)
	}
	var out settings
	if err := json.Unmarshal(b, &out); err != nil || !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip %+v %v", out, err)
	}
	if m, ok := out.TCP.Lookup(); !ok || m.TCP.Name != "tlsrec-1s" {
		t.Fatalf("lookup %+v %v", m, ok)
	}
	if m, ok := out.UDP.Lookup(); !ok || m.UDP.Name != "udp-zero-ttl3" {
		t.Fatalf("UDP lookup %+v %v", m, ok)
	}
	// A well-formed ID of another catalog version loads but is not found.
	if err := json.Unmarshal([]byte(`{"tcp":"s0123456789"}`), &out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out.TCP.Lookup(); ok {
		t.Fatal("unknown id found")
	}
	var empty ID
	if err := json.Unmarshal([]byte(`""`), &empty); err != nil || empty != "" {
		t.Fatalf("empty: %v", err)
	}
	if _, ok := empty.Lookup(); ok {
		t.Fatal("empty id found")
	}
	for _, bad := range []string{`"tlsrec-1s"`, `"s30879A4293"`, `"z30879a4293"`, `"s30879a429"`, `1`} {
		var id ID
		if err := json.Unmarshal([]byte(bad), &id); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if _, err := json.Marshal(ID("x")); err == nil {
		t.Error("malformed id marshalled")
	}
	if id, err := ParseID("u044556c7c3"); err != nil || id.String() != "u044556c7c3" {
		t.Errorf("ParseID: %v", err)
	}
	if got := IDs(TCP()[:2]); !reflect.DeepEqual(got, []string{"s21c85503c1", "s30879a4293"}) {
		t.Errorf("IDs %v", got)
	}
	if got := UDPIDs(UDP()[:1]); !reflect.DeepEqual(got, []string{"u6ebe839e20"}) {
		t.Errorf("UDPIDs %v", got)
	}
}

func TestFeatureStrings(t *testing.T) {
	want := map[Feature]string{FeatureDisorder: "disorder", FeatureOOB: "oob", FeatureFakeTCP: "fake-tcp",
		FeatureSplitWaitSent: "split-wait-sent", FeatureSplitWaitAcked: "split-wait-acked", FeatureFakeUDP: "fake-udp"}
	for f, s := range want {
		if f.String() != s {
			t.Errorf("%d: %s, want %s", f, f, s)
		}
	}
	if ok, why := Feature(99).Check(simulated("linux")); ok || !strings.Contains(why, "Feature(99)") {
		t.Errorf("unknown feature: %v %q", ok, why)
	}
}

type noProber struct{}

func (noProber) Probe(context.Context, controller.Target, string) (controller.Proof, error) {
	return controller.Proof{}, errors.New("not used")
}

// The documented controller setup: preset IDs as candidates, CatalogVersion
// in the policy version.
func TestControllerCandidates(t *testing.T) {
	usable, _ := Available(desync.PlatformCapabilities())
	ids := IDs(Ranked(usable)[1:])
	v := CatalogVersion(ids)
	if len(v) != 17 || v != CatalogVersion(append([]string(nil), ids...)) {
		t.Fatalf("version %q", v)
	}
	if v == CatalogVersion(ids[1:]) || v == CatalogVersion(append([]string{ids[1], ids[0]}, ids[2:]...)) ||
		CatalogVersion([]string{"ab", "c"}) == CatalogVersion([]string{"a", "bc"}) {
		t.Fatal("version does not follow the candidates")
	}
	all := append(IDs(TCP()), UDPIDs(UDP())...)
	c, err := controller.New(controller.Config{Candidates: all, PolicyVersion: "app-probe-v1:" + CatalogVersion(all)}, noProber{})
	if err != nil {
		t.Fatalf("controller rejects the catalog IDs: %v", err)
	}
	c.Close()
}
