package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Nemu-x/desync"
	"github.com/Nemu-x/desync/presets"
)

// preset is one named strategy of the shared catalog or the custom one.
type preset = presets.Preset

// skippedPreset is a catalog entry this platform cannot run.
type skippedPreset = presets.Skipped

// baselineName is the preset without any transformation. It is always run,
// so every other result can be compared with the direct connection.
const baselineName = presets.BaselineName

// availablePresets returns the shared TCP catalog in its stable order, kept
// to what caps provides and Options.Validate accepts here, and the rest with
// the reason.
func availablePresets(caps desync.Capabilities) ([]preset, []skippedPreset) {
	return presets.Available(caps)
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
	return preset{Name: name, Description: "custom strategy from the command line", Options: opts}, nil
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
