package desync

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// maxTTLCandidates bounds a TTL range expansion; a discovery budget (for
// example controller.Config.MaxAttempts, default 8) is usually far smaller.
const maxTTLCandidates = 64

func validTTLRange(from, to int) error {
	if from < 1 || to > 255 || from > to {
		return fmt.Errorf("desync: TTL range must satisfy 1 <= from <= to <= 255")
	}
	if to-from+1 > maxTTLCandidates {
		return fmt.Errorf("desync: TTL range must have at most %d values", maxTTLCandidates)
	}
	return nil
}

// FakeTTLCandidates expands a TTL range into one Options per TTL, in
// ascending order: copies of base with Fake.TTL set to from..to and
// Fake.AutoTTL cleared. It is the deterministic fallback where the path
// cannot be observed (see PlatformCapabilities().AutoTTL): register each
// candidate under an ID derived from its Key, which is stable for a given
// base and TTL, and let automatic discovery probe them. base.Fake must be
// set; the candidates share base's slices, which WrapConn copies.
func FakeTTLCandidates(base Options, from, to int) ([]Options, error) {
	if base.Fake == nil {
		return nil, fmt.Errorf("desync: TTL candidates need Fake options")
	}
	if err := validTTLRange(from, to); err != nil {
		return nil, err
	}
	out := make([]Options, 0, to-from+1)
	for ttl := from; ttl <= to; ttl++ {
		o := base
		fake := *base.Fake
		fake.TTL, fake.AutoTTL = ttl, nil
		o.Fake = &fake
		out = append(out, o)
	}
	return out, nil
}

// UDPTTLCandidates is FakeTTLCandidates for the UDP burst. The burst precedes
// the peer's first reply, so there is no packet whose TTL could be observed
// in time; a TTL range probed by discovery, or AutoTTL.TTL applied to the
// hops ObserveHops measured on a TCP connection to the same server, selects
// it instead.
func UDPTTLCandidates(base UDPOptions, from, to int) ([]UDPOptions, error) {
	if err := validTTLRange(from, to); err != nil {
		return nil, err
	}
	out := make([]UDPOptions, 0, to-from+1)
	for ttl := from; ttl <= to; ttl++ {
		o := base
		o.TTL = ttl
		out = append(out, o)
	}
	return out, nil
}

// Key returns a stable, canonical description of the fields that affect the
// UDP burst, like Options.Key (Counters is not part of it). The payload is
// represented by its SHA-256 digest.
func (o UDPOptions) Key() string {
	var b strings.Builder
	b.WriteString(keyVersion)
	b.WriteString(";udp=ttl:")
	b.WriteString(strconv.Itoa(o.TTL))
	b.WriteString(",repeats:")
	b.WriteString(strconv.Itoa(o.Repeats))
	b.WriteString(",packets:")
	b.WriteString(strconv.Itoa(o.Packets))
	b.WriteString(",payload:")
	if len(o.Payload) == 0 {
		b.WriteString("default")
	} else {
		sum := sha256.Sum256(o.Payload)
		b.WriteString(hex.EncodeToString(sum[:]))
	}
	return b.String()
}
