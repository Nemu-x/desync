package desync

import "sort"

func (f helloFrame) cuts(positions []Pos, recordOnly bool) []int {
	var cuts []int
	end := f.handshakeEnd()
	for _, p := range positions {
		at := p.Offset
		if p.FromSNI {
			if f.sniLogical < 0 || p.Offset < -f.sniLogical || p.Offset >= f.size-f.sniLogical {
				continue
			}
			at = f.byteOffset(f.sniLogical + p.Offset)
		}
		if at > 0 && at < end {
			cuts = append(cuts, at)
		}
	}
	sort.Ints(cuts)
	unique := cuts[:0]
	span := 0
	for i, at := range cuts {
		if i > 0 && at == cuts[i-1] {
			continue
		}
		if recordOnly {
			for span+1 < f.records.count && at >= f.records.at(span).end {
				span++
			}
			r := f.records.at(span)
			if at <= r.start+recordHeaderLen || at >= r.end {
				continue
			}
		}
		unique = append(unique, at)
	}
	return unique
}

// fragmentHello preserves original record boundaries/versions and any bytes
// coalesced after the hello. Only explicitly requested interior cuts add headers.
func fragmentHello(wire []byte, frame helloFrame, cuts []int) []byte {
	out := make([]byte, 0, len(wire)+recordHeaderLen*len(cuts))
	cut := 0
	for i := 0; i < frame.records.count; i++ {
		r := frame.records.at(i)
		if cut == len(cuts) || cuts[cut] >= r.end {
			out = append(out, wire[r.start:r.end]...)
			continue
		}
		start := r.start + recordHeaderLen
		for cut < len(cuts) && cuts[cut] < r.end {
			end := cuts[cut]
			n := end - start
			out = append(out, wire[r.start], wire[r.start+1], wire[r.start+2], byte(n>>8), byte(n))
			out = append(out, wire[start:end]...)
			start = end
			cut++
		}
		n := r.end - start
		out = append(out, wire[r.start], wire[r.start+1], wire[r.start+2], byte(n>>8), byte(n))
		out = append(out, wire[start:r.end]...)
	}
	return out
}

// FragmentRecord splits one TLS record into several records at the given
// absolute offsets (header included in the numbering, like ParseHello's
// offsets). Every piece gets its own 5-byte header with the original content
// type and version, so the peer reassembles the same handshake message; a DPI
// box that only reads the first record no longer sees the whole ClientHello.
// Offsets outside the payload are ignored; rec is not modified.
func FragmentRecord(rec []byte, cuts []int) []byte {
	if len(rec) < recordHeaderLen {
		return append([]byte(nil), rec...)
	}
	var at []int
	for _, c := range cuts {
		if c > recordHeaderLen && c < len(rec) {
			at = append(at, c)
		}
	}
	if len(at) == 0 {
		return append([]byte(nil), rec...)
	}
	out := make([]byte, 0, len(rec)+recordHeaderLen*len(at))
	start := recordHeaderLen
	for _, end := range append(at, len(rec)) {
		if end <= start {
			continue
		}
		n := end - start
		out = append(out, rec[0], rec[1], rec[2], byte(n>>8), byte(n))
		out = append(out, rec[start:end]...)
		start = end
	}
	return out
}
