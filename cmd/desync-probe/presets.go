package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Nemu-x/desync"
)

// preset is one named strategy of the built-in catalog or the custom one.
type preset struct {
	Name        string
	Description string
	Opts        desync.Options
	// needs lists the platform features the preset depends on; buildCatalog
	// skips the preset when one of them is missing.
	needs []feature
}

// ID is stable for a given Options value: it is derived from Options.Key(),
// so it changes exactly when the transformation would change.
func (p preset) ID() string { return strategyID(p.Opts) }

func strategyID(o desync.Options) string {
	sum := sha256.Sum256([]byte(o.Key()))
	return "s" + hex.EncodeToString(sum[:5])
}

// feature is a platform capability a preset needs.
type feature uint8

const (
	featDisorder feature = iota + 1
	featOOB
	featFakeTCP
	featWaitSent
	featWaitAcked
)

// available reports whether caps provides f, and if not, why.
func (f feature) available(caps desync.Capabilities) (bool, string) {
	why := func(key, fallback string) string {
		if r := caps.Unsupported[key]; r != "" {
			return key + ": " + r
		}
		return fallback + " on " + caps.OS
	}
	switch f {
	case featDisorder:
		return caps.Disorder.Supported, why("disorder", "disorder is not implemented")
	case featOOB:
		return caps.OOB, why("oob", "out-of-band data is not implemented")
	case featFakeTCP:
		return caps.FakeTCP, why("fake-tcp", "the TCP fake is not implemented")
	case featWaitSent:
		return caps.Ack.Sent, why("split-wait-sent", "split wait \"sent\" cannot be observed")
	case featWaitAcked:
		return caps.Ack.Acked, why("split-wait-acked", "split wait \"acked\" cannot be observed")
	}
	return false, "unknown feature"
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

// baselineName is the preset without any transformation. It is always run,
// so every other result can be compared with the direct connection.
const baselineName = "none"

// catalog returns every built-in preset, independent of the platform.
func catalog() []preset {
	fake := func(ttl int) preset {
		return preset{
			Name:        fmt.Sprintf("fake-ttl%d", ttl),
			Description: fmt.Sprintf("low-TTL fake first transmission of all but the last byte, TTL %d", ttl),
			Opts:        desync.Options{Fake: &desync.FakeOptions{TTL: ttl, Prefix: -1}},
			needs:       []feature{featFakeTCP},
		}
	}
	return []preset{
		{Name: baselineName, Description: "direct connection, no transformation (baseline)"},
		{Name: "tlsrec-1s", Description: "TLS records split 1 byte into the server name (--tlsrec 1+s)",
			Opts: desync.Options{TLSRec: posList("1+s")}},
		{Name: "tlsrec-3s", Description: "TLS records split 3 bytes into the server name (--tlsrec 3+s)",
			Opts: desync.Options{TLSRec: posList("3+s")}},
		{Name: "tlsrec-before-sni", Description: "TLS records split 2 bytes before the server name (--tlsrec -2+s)",
			Opts: desync.Options{TLSRec: posList("-2+s")}},
		{Name: "tlsrec-multi", Description: "TLS records split at 1+s, 5+s and 10+s",
			Opts: desync.Options{TLSRec: posList("1+s", "5+s", "10+s")}},
		{Name: "split-1", Description: "TCP writes split after byte 1 (--split 1)",
			Opts: desync.Options{Split: posList("1")}},
		{Name: "split-1s", Description: "TCP writes split 1 byte into the server name (--split 1+s)",
			Opts: desync.Options{Split: posList("1+s")}},
		{Name: "tlsrec-1s-split-1", Description: "TLS records at 1+s and TCP writes split after byte 1",
			Opts: desync.Options{TLSRec: posList("1+s"), Split: posList("1")}},
		{Name: "random-tlsrec", Description: "two random TLS record cuts within 8 bytes of the server name, new cuts per connection",
			Opts: desync.Options{Random: &desync.RandomOptions{TLSRec: []desync.RandomCut{{From: pos("-8+s"), To: pos("8+s"), Count: 2, MinPiece: 2}}}}},
		{Name: "random-split", Description: "one random TCP write cut between bytes 1 and 120, new cut per connection",
			Opts: desync.Options{Random: &desync.RandomOptions{Split: []desync.RandomCut{{From: pos("1"), To: pos("120")}}}}},
		{Name: "disorder-1", Description: "split after byte 1, first piece sent with hop limit 1 (--disorder 1)",
			Opts: desync.Options{Split: posList("1"), Disorder: true}, needs: []feature{featDisorder}},
		{Name: "disorder-1s", Description: "split at 1+s, first piece sent with hop limit 1 (--disorder 1+s)",
			Opts: desync.Options{Split: posList("1+s"), Disorder: true}, needs: []feature{featDisorder}},
		{Name: "oob-1", Description: "split after byte 1 with one out-of-band byte (--oob 1)",
			Opts: desync.Options{Split: posList("1"), OOB: &desync.OOBOptions{}}, needs: []feature{featOOB}},
		{Name: "oob-1s", Description: "split at 1+s with one out-of-band byte (--oob 1+s)",
			Opts: desync.Options{Split: posList("1+s"), OOB: &desync.OOBOptions{}}, needs: []feature{featOOB}},
		{Name: "disoob-1s", Description: "split at 1+s, hop limit 1 and an out-of-band byte (--disoob 1+s)",
			Opts: desync.Options{Split: posList("1+s"), Disorder: true, OOB: &desync.OOBOptions{}}, needs: []feature{featDisorder, featOOB}},
		{Name: "split-1s-wait-sent", Description: "split at 1+s, second piece only after the first was transmitted",
			Opts: desync.Options{Split: posList("1+s"), SplitWait: desync.SplitWaitSent}, needs: []feature{featWaitSent}},
		{Name: "split-1s-wait-acked", Description: "split at 1+s, second piece only after the first was acknowledged",
			Opts: desync.Options{Split: posList("1+s"), SplitWait: desync.SplitWaitAcked}, needs: []feature{featWaitAcked}},
		fake(3),
		fake(5),
		fake(8),
		{Name: "fake-ttl5-sni", Description: "low-TTL fake whose decoy ClientHello names www.wikipedia.org, randomized per connection, TTL 5",
			Opts:  desync.Options{Fake: &desync.FakeOptions{TTL: 5, Prefix: -1, SNI: []string{"www.wikipedia.org"}, Randomize: true}},
			needs: []feature{featFakeTCP}},
		{Name: "split-1s-fake-ttl5", Description: "split at 1+s, the piece from there to the last byte sent first as a low-TTL fake, TTL 5",
			Opts:  desync.Options{Split: posList("1+s"), Fake: &desync.FakeOptions{TTL: 5, Prefix: -1}},
			needs: []feature{featFakeTCP}},
		{Name: "disorder-1-fake-ttl5", Description: "split after byte 1 with hop limit 1 on the first piece, the rest sent first as a low-TTL fake, TTL 5",
			Opts:  desync.Options{Split: posList("1"), Disorder: true, Fake: &desync.FakeOptions{TTL: 5, Prefix: -1}},
			needs: []feature{featDisorder, featFakeTCP}},
	}
}

// skippedPreset is a catalog entry this platform cannot run.
type skippedPreset struct {
	Name   string
	Key    string
	Reason string
}

// buildCatalog keeps the presets whose features caps provides and lists the
// others with the reason. It looks only at caps, so it can be tested with
// any platform's capabilities.
func buildCatalog(all []preset, caps desync.Capabilities) ([]preset, []skippedPreset) {
	var usable []preset
	var skipped []skippedPreset
	for _, p := range all {
		ok, reason := true, ""
		for _, f := range p.needs {
			if have, why := f.available(caps); !have {
				ok, reason = false, why
				break
			}
		}
		if ok {
			usable = append(usable, p)
		} else {
			skipped = append(skipped, skippedPreset{Name: p.Name, Key: p.Opts.Key(), Reason: reason})
		}
	}
	return usable, skipped
}

// validateCatalog drops presets that Options.Validate rejects on this
// platform; buildCatalog should already have excluded them.
func validateCatalog(ps []preset) ([]preset, []skippedPreset) {
	var usable []preset
	var skipped []skippedPreset
	for _, p := range ps {
		if err := p.Opts.Validate(); err != nil {
			skipped = append(skipped, skippedPreset{Name: p.Name, Key: p.Opts.Key(), Reason: err.Error()})
			continue
		}
		usable = append(usable, p)
	}
	return usable, skipped
}

// selectPresets keeps the presets named in spec ("all", or a comma-separated
// list of names). The baseline is always kept and always first.
func selectPresets(ps []preset, spec string) ([]preset, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "all" {
		return ps, nil
	}
	want := map[string]bool{}
	for _, n := range strings.Split(spec, ",") {
		if n = strings.TrimSpace(n); n != "" {
			want[n] = true
		}
	}
	var out []preset
	for _, p := range ps {
		if p.Name == baselineName || want[p.Name] {
			out = append(out, p)
			delete(want, p.Name)
		}
	}
	delete(want, baselineName)
	if len(want) > 0 {
		var unknown []string
		for n := range want {
			unknown = append(unknown, n)
		}
		return nil, fmt.Errorf("unknown or unavailable preset(s): %s (see -list-presets)", strings.Join(sortedStrings(unknown), ", "))
	}
	return out, nil
}

// customFlags holds the desync-socks style flags of a custom strategy.
type customFlags struct {
	name, tlsrec, split, wait, oobByte string
	delay, waitTimeout, fakeTimeout    time.Duration
	fake, ttl                          int
	disorder, oob                      bool
}

func (c customFlags) set() bool {
	return c.tlsrec != "" || c.split != "" || c.fake != 0 || c.disorder || c.oob ||
		(c.wait != "" && c.wait != "none") || c.delay != 0
}

func (c customFlags) preset() (preset, error) {
	opts := desync.Options{SplitDelay: c.delay, SplitWaitTimeout: c.waitTimeout, Disorder: c.disorder}
	var err error
	if opts.TLSRec, err = parseList(c.tlsrec); err != nil {
		return preset{}, err
	}
	if opts.Split, err = parseList(c.split); err != nil {
		return preset{}, err
	}
	if opts.SplitWait, err = desync.ParseSplitWait(c.wait); err != nil {
		return preset{}, err
	}
	if c.oob {
		b, err := parseByte(c.oobByte)
		if err != nil {
			return preset{}, err
		}
		opts.OOB = &desync.OOBOptions{Byte: b}
	}
	if c.fake != 0 {
		opts.Fake = &desync.FakeOptions{TTL: c.ttl, Prefix: c.fake, Timeout: c.fakeTimeout}
	}
	if err := opts.Validate(); err != nil {
		return preset{}, fmt.Errorf("custom strategy: %w", err)
	}
	name := strings.TrimSpace(c.name)
	if name == "" {
		name = "custom"
	}
	if strings.ContainsAny(name, ", \t") {
		return preset{}, fmt.Errorf("custom strategy name %q must not contain commas or spaces", name)
	}
	return preset{Name: name, Description: "custom strategy from the command line", Opts: opts}, nil
}

// addCustom appends the custom preset unless an identical strategy (same ID)
// or name is already present.
func addCustom(ps []preset, c preset) ([]preset, error) {
	for _, p := range ps {
		if p.ID() == c.ID() {
			return ps, nil
		}
		if p.Name == c.Name {
			return nil, fmt.Errorf("custom strategy name %q is already used by a preset; choose another with -name", c.Name)
		}
	}
	return append(ps, c), nil
}

func parseList(s string) ([]desync.Pos, error) {
	var out []desync.Pos
	for _, f := range strings.Split(s, ",") {
		if strings.TrimSpace(f) == "" {
			continue
		}
		p, err := desync.ParsePos(f)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// parseByte parses one character or a 0x-prefixed hex byte.
func parseByte(s string) (byte, error) {
	if strings.HasPrefix(s, "0x") {
		v, err := strconv.ParseUint(s[2:], 16, 8)
		if err != nil {
			return 0, fmt.Errorf("bad byte %q", s)
		}
		return byte(v), nil
	}
	if len(s) != 1 {
		return 0, fmt.Errorf("bad byte %q: want one character or 0xNN", s)
	}
	return s[0], nil
}
