// Package presets is the shared strategy catalog of desync: named TCP
// transformations (desync.Options) and UDP bursts (desync.UDPOptions) with
// stable IDs, the platform features each one needs, and an ordering hint.
//
// Applications, cmd/desync-probe and the optional controller use the same
// presets and the same IDs, so a probe report, a cached controller choice and
// a persisted user setting all name the same transformation. An ID is derived
// from the options' Key, so it changes exactly when the transformation would
// change; persist IDs, never option values, and take the options from the
// catalog when the ID is used.
//
// The catalog says what can be tried, not what works: effectiveness depends on
// the network and must be measured there (desync-probe, or the controller with
// an application probe).
package presets

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/Nemu-x/desync"
)

// BaselineName is the name of the TCP preset without any transformation. It
// is first in TCP and in Ranked order, so other results can be compared with
// the direct connection; an application that only wants transformations can
// drop it (its Options.Enabled() is false).
const BaselineName = "none"

// Preset is one named TCP strategy. Options is the single source of truth:
// the ID, the key and the behavior all derive from it.
type Preset struct {
	Name        string
	Description string
	Options     desync.Options
	// Needs lists the platform features the preset depends on; Available
	// skips the preset when one of them is missing.
	Needs []Feature
	// Rank orders presets by cost and risk, lower first (see Ranked).
	Rank int
}

// ID is the stable short ID of the preset, OptionsID(p.Options).
func (p Preset) ID() string { return OptionsID(p.Options) }

// Key is p.Options.Key().
func (p Preset) Key() string { return p.Options.Key() }

// UDPPreset is one named low-TTL UDP burst. Options is the single source of
// truth; Options.Counters is nil in the catalog and may be set by the caller
// on its copy.
type UDPPreset struct {
	Name        string
	Description string
	Options     desync.UDPOptions
	Needs       []Feature
	Rank        int
}

// ID is the stable short ID of the preset, UDPOptionsID(p.Options).
func (p UDPPreset) ID() string { return UDPOptionsID(p.Options) }

// Key is p.Options.Key().
func (p UDPPreset) Key() string { return p.Options.Key() }

// idHexLen is the number of hex digits after the one-letter prefix.
const idHexLen = 10

// OptionsID returns "s" followed by the first 10 hex digits of the SHA-256 of
// o.Key(). It is the ID desync-probe reports, so IDs in reports, caches and
// settings are comparable; use it for custom strategies too.
func OptionsID(o desync.Options) string { return shortID('s', o.Key()) }

// UDPOptionsID returns "u" followed by the first 10 hex digits of the SHA-256
// of o.Key(). The prefix keeps TCP and UDP IDs apart.
func UDPOptionsID(o desync.UDPOptions) string { return shortID('u', o.Key()) }

func shortID(prefix byte, key string) string {
	sum := sha256.Sum256([]byte(key))
	return string(prefix) + hex.EncodeToString(sum[:idHexLen/2])
}

// Feature is a platform capability a preset needs.
type Feature uint8

const (
	FeatureDisorder Feature = iota + 1
	FeatureOOB
	FeatureFakeTCP
	FeatureSplitWaitSent
	FeatureSplitWaitAcked
	FeatureFakeUDP
)

// String returns the method name used as the key of
// desync.Capabilities.Unsupported where there is one.
func (f Feature) String() string {
	switch f {
	case FeatureDisorder:
		return "disorder"
	case FeatureOOB:
		return "oob"
	case FeatureFakeTCP:
		return "fake-tcp"
	case FeatureSplitWaitSent:
		return "split-wait-sent"
	case FeatureSplitWaitAcked:
		return "split-wait-acked"
	case FeatureFakeUDP:
		return "fake-udp"
	}
	return fmt.Sprintf("Feature(%d)", uint8(f))
}

// Check reports whether caps provides f and, if not, why: the reason from
// caps.Unsupported prefixed with the method name, or a generic reason naming
// caps.OS.
func (f Feature) Check(caps desync.Capabilities) (bool, string) {
	why := func(fallback string) string {
		if r := caps.Unsupported[f.String()]; r != "" {
			return f.String() + ": " + r
		}
		return fallback + " on " + caps.OS
	}
	switch f {
	case FeatureDisorder:
		return caps.Disorder.Supported, why("disorder is not implemented")
	case FeatureOOB:
		return caps.OOB, why("out-of-band data is not implemented")
	case FeatureFakeTCP:
		return caps.FakeTCP, why("the TCP fake is not implemented")
	case FeatureSplitWaitSent:
		return caps.Ack.Sent, why("split wait \"sent\" cannot be observed")
	case FeatureSplitWaitAcked:
		return caps.Ack.Acked, why("split wait \"acked\" cannot be observed")
	case FeatureFakeUDP:
		return caps.FakeUDP, why("the UDP burst is not implemented")
	}
	return false, "unknown feature " + f.String()
}

// missing returns the reason for the first feature of needs that caps lacks.
func missing(needs []Feature, caps desync.Capabilities) (string, bool) {
	for _, f := range needs {
		if ok, why := f.Check(caps); !ok {
			return why, true
		}
	}
	return "", false
}

// Skipped is a preset a platform cannot run, with the reason.
type Skipped struct {
	Name   string
	Key    string
	Reason string
}

// Filter keeps the presets of ps whose features caps provides, in order, and
// lists the others with the reason. It looks only at caps, not at the running
// system, so it can answer for any platform's capabilities.
func Filter(ps []Preset, caps desync.Capabilities) (usable []Preset, skipped []Skipped) {
	for _, p := range ps {
		if why, ok := missing(p.Needs, caps); ok {
			skipped = append(skipped, Skipped{Name: p.Name, Key: p.Key(), Reason: why})
			continue
		}
		usable = append(usable, p)
	}
	return usable, skipped
}

// FilterUDP is Filter for UDP presets.
func FilterUDP(ps []UDPPreset, caps desync.Capabilities) (usable []UDPPreset, skipped []Skipped) {
	for _, p := range ps {
		if why, ok := missing(p.Needs, caps); ok {
			skipped = append(skipped, Skipped{Name: p.Name, Key: p.Key(), Reason: why})
			continue
		}
		usable = append(usable, p)
	}
	return usable, skipped
}

// Available returns the TCP presets usable with caps, in catalog order, and
// the skipped ones: first those caps cannot run (Filter), then those that
// Options.Validate rejects on the running system, with its error as the
// reason. Pass desync.PlatformCapabilities() for this system; with another
// platform's capabilities the Validate step still checks the running system.
func Available(caps desync.Capabilities) (usable []Preset, skipped []Skipped) {
	kept, skipped := Filter(TCP(), caps)
	for _, p := range kept {
		if err := p.Options.Validate(); err != nil {
			skipped = append(skipped, Skipped{Name: p.Name, Key: p.Key(), Reason: err.Error()})
			continue
		}
		usable = append(usable, p)
	}
	return usable, skipped
}

// AvailableUDP is Available for the UDP catalog.
func AvailableUDP(caps desync.Capabilities) (usable []UDPPreset, skipped []Skipped) {
	kept, skipped := FilterUDP(UDP(), caps)
	for _, p := range kept {
		if err := p.Options.Validate(); err != nil {
			skipped = append(skipped, Skipped{Name: p.Name, Key: p.Key(), Reason: err.Error()})
			continue
		}
		usable = append(usable, p)
	}
	return usable, skipped
}

// Ranked returns a copy of ps ordered by Rank, catalog order within a rank.
// It is the suggested order for trying strategies (see the package README
// section "Strategy catalog" for the rationale); it does not say which one
// works.
func Ranked(ps []Preset) []Preset {
	out := append([]Preset(nil), ps...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Rank < out[j].Rank })
	return out
}

// RankedUDP is Ranked for UDP presets.
func RankedUDP(ps []UDPPreset) []UDPPreset {
	out := append([]UDPPreset(nil), ps...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Rank < out[j].Rank })
	return out
}

// IDs returns the IDs of ps in order, for example as controller candidates.
func IDs(ps []Preset) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.ID()
	}
	return out
}

// UDPIDs is IDs for UDP presets.
func UDPIDs(ps []UDPPreset) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.ID()
	}
	return out
}

// CatalogVersion returns "c" followed by 16 hex digits of the SHA-256 of the
// IDs in order. It changes when a candidate is added, removed, reordered or
// changes meaning, so it suits controller.Config.PolicyVersion (combined with
// the application's probe contract version, for example
// "app-probe-v1:" + CatalogVersion(ids)); joined IDs would exceed the
// controller's 128-byte limit.
func CatalogVersion(ids []string) string {
	h := sha256.New()
	for _, id := range ids {
		h.Write([]byte(id))
		h.Write([]byte{0})
	}
	return "c" + hex.EncodeToString(h.Sum(nil)[:8])
}

// Match is the result of ByID: exactly one of TCP and UDP is set.
type Match struct {
	TCP *Preset
	UDP *UDPPreset
}

// ByID finds the preset with the given ID in the TCP and UDP catalogs. The
// result is a fresh copy. An ID from an older or newer library version may
// not be found when the options behind it changed.
func ByID(id string) (Match, bool) {
	if len(id) != 1+idHexLen {
		return Match{}, false
	}
	switch id[0] {
	case 's':
		for _, p := range TCP() {
			if p.ID() == id {
				p := p
				return Match{TCP: &p}, true
			}
		}
	case 'u':
		for _, p := range UDP() {
			if p.ID() == id {
				p := p
				return Match{UDP: &p}, true
			}
		}
	}
	return Match{}, false
}
