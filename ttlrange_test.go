package desync

import (
	"strconv"
	"strings"
	"testing"
)

func TestFakeTTLCandidates(t *testing.T) {
	base := Options{TLSRec: []Pos{{Offset: 1, FromSNI: true}}, Fake: &FakeOptions{TTL: 9, Prefix: 20, AutoTTL: &AutoTTL{}}}
	baseKey := base.Key()
	got, err := FakeTTLCandidates(base, 2, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 7 {
		t.Fatalf("%d candidates", len(got))
	}
	again, _ := FakeTTLCandidates(base, 2, 8)
	seen := map[string]bool{}
	for i, o := range got {
		ttl := 2 + i
		if o.Fake == base.Fake || o.Fake.TTL != ttl || o.Fake.AutoTTL != nil || o.Fake.Prefix != 20 || len(o.TLSRec) != 1 {
			t.Fatalf("candidate %d: %+v", i, o.Fake)
		}
		want := Options{TLSRec: base.TLSRec, Fake: &FakeOptions{TTL: ttl, Prefix: 20}}
		if o.Key() != want.Key() || o.Key() != again[i].Key() {
			t.Fatalf("candidate %d key %s, want %s", i, o.Key(), want.Key())
		}
		if !strings.Contains(o.Key(), "fake=ttl:"+strconv.Itoa(ttl)+",") || strings.Contains(o.Key(), "auto:") {
			t.Fatalf("candidate %d key %s", i, o.Key())
		}
		if seen[o.Key()] {
			t.Fatalf("duplicate key %s", o.Key())
		}
		seen[o.Key()] = true
		if SupportsFake() {
			if err := o.Validate(); err != nil {
				t.Fatalf("candidate %d: %v", i, err)
			}
		}
	}
	if base.Fake.TTL != 9 || base.Fake.AutoTTL == nil || base.Key() != baseKey {
		t.Fatal("base was modified")
	}
	for _, r := range [][2]int{{0, 4}, {4, 256}, {5, 4}, {1, 65}, {-3, -1}} {
		if _, err := FakeTTLCandidates(base, r[0], r[1]); err == nil || !strings.HasPrefix(err.Error(), "desync: ") {
			t.Fatalf("range %v: %v", r, err)
		}
	}
	if one, err := FakeTTLCandidates(base, 255, 255); err != nil || len(one) != 1 {
		t.Fatalf("single TTL: %v %v", one, err)
	}
	if _, err := FakeTTLCandidates(Options{}, 2, 8); err == nil || !strings.HasPrefix(err.Error(), "desync: ") {
		t.Fatalf("no fake: %v", err)
	}
}

func TestUDPTTLCandidatesAndKey(t *testing.T) {
	const want = "desync/v1;udp=ttl:4,repeats:0,packets:0,payload:default"
	if got := (UDPOptions{TTL: 4}).Key(); got != want {
		t.Fatalf("key %s, want %s", got, want)
	}
	if (UDPOptions{TTL: 4, Counters: &UDPCounters{}}).Key() != want {
		t.Fatal("counters change the key")
	}
	if (UDPOptions{TTL: 4, Payload: []byte{1}}).Key() == (UDPOptions{TTL: 4, Payload: []byte{2}}).Key() {
		t.Fatal("payload not in the key")
	}
	base := UDPOptions{TTL: 9, Repeats: 2, Packets: 1, Payload: []byte("x")}
	got, err := UDPTTLCandidates(base, 3, 6)
	if err != nil || len(got) != 4 {
		t.Fatalf("%d %v", len(got), err)
	}
	seen := map[string]bool{}
	for i, o := range got {
		w := base
		w.TTL = 3 + i
		if o.TTL != 3+i || o.Key() != w.Key() || seen[o.Key()] {
			t.Fatalf("candidate %d: %+v %s", i, o, o.Key())
		}
		seen[o.Key()] = true
		if SupportsUDPFake() {
			if err := o.Validate(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := UDPTTLCandidates(base, 9, 2); err == nil {
		t.Fatal("inverted range accepted")
	}
}
