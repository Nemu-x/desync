package desync

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Pos is a position in the first TLS record of a connection: an absolute byte
// offset, or an offset from the start of the server name ("+s").
type Pos struct {
	Offset  int
	FromSNI bool
}

// ParsePos parses "3" (byte 3 of the record) or "1+s" / "-2+s" (relative to
// the first byte of the server name). It is the notation ByeDPI uses.
func ParsePos(s string) (Pos, error) {
	s = strings.TrimSpace(s)
	fromSNI := false
	if strings.HasSuffix(s, "+s") {
		fromSNI = true
		s = strings.TrimSuffix(s, "+s")
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return Pos{}, fmt.Errorf("desync: bad position %q: want N or N+s", s)
	}
	return Pos{Offset: n, FromSNI: fromSNI}, nil
}

func (p Pos) String() string {
	if p.FromSNI {
		return strconv.Itoa(p.Offset) + "+s"
	}
	return strconv.Itoa(p.Offset)
}

// resolve turns positions into sorted, distinct absolute offsets strictly
// inside (lo, hi). Positions relative to a missing SNI are dropped.
func resolve(ps []Pos, h Hello, lo, hi int) []int {
	var out []int
	seen := map[int]bool{}
	for _, p := range ps {
		at := p.Offset
		if p.FromSNI {
			if h.SNIOffset < 0 {
				continue
			}
			at += h.SNIOffset
		}
		if at <= lo || at >= hi || seen[at] {
			continue
		}
		seen[at] = true
		out = append(out, at)
	}
	sort.Ints(out)
	return out
}
