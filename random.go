package desync

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
)

const (
	// MaxRandomRanges bounds RandomOptions.TLSRec and RandomOptions.Split each.
	MaxRandomRanges = 16
	// MaxRandomCount bounds RandomCut.Count, the cuts drawn from one range.
	MaxRandomCount = 64
)

// RandomOptions adds bounded random cuts to the deterministic TLSRec/Split
// positions. It is opt-in: a nil Options.Random keeps a strategy fully
// deterministic, and the deterministic positions keep their exact meaning
// when randomization is enabled; random cuts are only added to them.
//
// Random cuts are drawn once per connection, for its first ClientHello. They
// never change logical handshake bytes, never create an empty TLS record or an
// empty write, and add no delay beyond an explicitly configured SplitDelay.
type RandomOptions struct {
	// TLSRec ranges add TLS record boundaries (randomized --tlsrec).
	TLSRec []RandomCut
	// Split ranges add TCP write boundaries (randomized --split). Like Split,
	// they cannot be combined with Fake yet.
	Split []RandomCut
	// Seed makes the draws reproducible: every connection wrapped with the
	// same nonzero Seed and options cuts the same ClientHello identically,
	// which is meant for tests and bug reports. Zero (the default) draws an
	// independent seed from crypto/rand for every connection.
	Seed uint64
}

// RandomCut draws Count cut positions uniformly from the inclusive range
// [From, To]. Both ends use one anchor: absolute (wire offsets, like Pos) or
// SNI-relative (logical handshake bytes from the server name, like "+s").
//
// Cuts are chosen among logical handshake byte boundaries, so an absolute
// range never places a cut inside an existing record header; a wire offset in
// a header means the start of that record's payload. The range is clipped to
// the ClientHello; an SNI-relative range is ignored without an SNI, like Pos.
//
// MinPiece is the minimum distance between two cuts of this range and from
// either end of the handshake. When the clipped range cannot hold Count cuts
// at that spacing, as many as fit are drawn. A random cut that coincides with
// another cut or an existing record boundary adds nothing.
type RandomCut struct {
	From, To Pos
	// Count is 1..MaxRandomCount; zero means one cut.
	Count int
	// MinPiece is 1..ClientHello max size bytes; zero means one byte.
	MinPiece int
}

func (r *RandomOptions) enabled() bool {
	return r != nil && (len(r.TLSRec) > 0 || len(r.Split) > 0)
}

func (r *RandomOptions) clone() *RandomOptions {
	if r == nil {
		return nil
	}
	c := *r
	c.TLSRec = append([]RandomCut(nil), r.TLSRec...)
	c.Split = append([]RandomCut(nil), r.Split...)
	return &c
}

func (r *RandomOptions) validate(limits helloLimits) error {
	if r == nil {
		return nil
	}
	for _, list := range [...]struct {
		name string
		cuts []RandomCut
	}{{"TLSRec", r.TLSRec}, {"Split", r.Split}} {
		if len(list.cuts) > MaxRandomRanges {
			return fmt.Errorf("desync: at most %d random %s ranges", MaxRandomRanges, list.name)
		}
		for _, c := range list.cuts {
			if c.From.FromSNI != c.To.FromSNI {
				return fmt.Errorf("desync: random %s range %s..%s mixes absolute and SNI-relative ends", list.name, c.From, c.To)
			}
			if c.From.Offset > c.To.Offset {
				return fmt.Errorf("desync: random %s range %s..%s is reversed", list.name, c.From, c.To)
			}
			if c.Count < 0 || c.Count > MaxRandomCount {
				return fmt.Errorf("desync: random %s count must be between 1 and %d", list.name, MaxRandomCount)
			}
			if c.MinPiece < 0 || c.MinPiece > limits.size {
				return fmt.Errorf("desync: random %s minimum piece must be between 1 and %d", list.name, limits.size)
			}
		}
	}
	return nil
}

// cutRand is splitmix64: tiny, allocation-free and fully determined by its
// 64-bit state, so a Seed reproduces the same draws on every platform.
type cutRand struct{ state uint64 }

func (r *cutRand) next() uint64 {
	r.state += 0x9e3779b97f4a7c15
	z := r.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// intn returns an unbiased value in [0, n) for n > 0.
func (r *cutRand) intn(n int) int {
	bound := uint64(n)
	threshold := -bound % bound
	for {
		if x := r.next(); x >= threshold {
			return int(x % bound)
		}
	}
}

// newCutRand seeds one connection's draws. Unseeded policies read a 64-bit
// seed from crypto/rand once per connection, so a consumer calling the global
// math/rand.Seed cannot make all connections alike; the draws themselves then
// use the cheap generator above. A failing system source falls back to the
// auto-seeded global math/rand source.
func (c *Conn) newCutRand() cutRand {
	if seed := c.opts.Random.Seed; seed != 0 {
		return cutRand{seed}
	}
	var b [8]byte
	if _, err := crand.Read(b[:]); err == nil {
		return cutRand{binary.LittleEndian.Uint64(b[:])}
	}
	return cutRand{mrand.Uint64()}
}

// randomCutCapacity is the most cuts the ranges can draw.
func randomCutCapacity(ranges []RandomCut) int {
	n := 0
	for _, rc := range ranges {
		if rc.Count < 1 {
			n++
		} else {
			n += rc.Count
		}
	}
	return n
}

// logicalAt maps an absolute wire offset to a logical handshake boundary. An
// offset inside a record header becomes the start of that record's payload.
func (f helloFrame) logicalAt(wire int) int {
	logical := 0
	for i := 0; i < f.records.count; i++ {
		r := f.records.at(i)
		payload := r.start + recordHeaderLen
		if wire < payload {
			return logical
		}
		if wire < r.end {
			return logical + wire - payload
		}
		logical += r.end - payload
	}
	return logical
}

// randomCuts appends original wire offsets for every range to cuts. The
// caller sorts, deduplicates and filters them with the deterministic cuts.
func (f helloFrame) randomCuts(cuts []int, ranges []RandomCut, rng *cutRand) []int {
	var picks [MaxRandomCount]int
	for _, rc := range ranges {
		var lo, hi int
		if rc.From.FromSNI {
			if f.sniLogical < 0 {
				continue
			}
			lo, hi = f.sniLogical+rc.From.Offset, f.sniLogical+rc.To.Offset
		} else {
			lo, hi = f.logicalAt(rc.From.Offset), f.logicalAt(rc.To.Offset)
		}
		gap := rc.MinPiece
		if gap < 1 {
			gap = 1
		}
		if lo < gap {
			lo = gap
		}
		if hi > f.size-gap {
			hi = f.size - gap
		}
		if hi < lo {
			continue
		}
		n := rc.Count
		if n < 1 {
			n = 1
		}
		if fit := (hi-lo)/gap + 1; n > fit {
			n = fit
		}
		// Choosing n distinct values from [0, slots) and spreading the sorted
		// values by gap-1 gives a uniform choice among all spaced cut sets.
		slots := hi - lo + 1 - (n-1)*(gap-1)
		chosen := picks[:0]
		for j := slots - n; j < slots; j++ { // Floyd's subset sampling.
			v := rng.intn(j + 1)
			for _, p := range chosen {
				if p == v {
					v = j
					break
				}
			}
			chosen = append(chosen, v)
		}
		for i := 1; i < len(chosen); i++ { // insertion sort; n is small.
			for k := i; k > 0 && chosen[k] < chosen[k-1]; k-- {
				chosen[k], chosen[k-1] = chosen[k-1], chosen[k]
			}
		}
		for i, v := range chosen {
			cuts = append(cuts, f.byteOffset(lo+v+i*(gap-1)))
		}
	}
	return cuts
}
