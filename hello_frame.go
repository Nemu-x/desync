package desync

import "strings"

type helloRecord struct{ start, end int }
type helloRecords struct {
	first helloRecord
	more  []helloRecord
	count int
}

func (r *helloRecords) add(span helloRecord) {
	if r.count == 0 {
		r.first = span
	} else {
		r.more = append(r.more, span)
	}
	r.count++
}
func (r helloRecords) at(i int) helloRecord {
	if i == 0 {
		return r.first
	}
	return r.more[i-1]
}

type helloFrame struct {
	hello                     Hello
	records                   helloRecords
	size, wireLen, sniLogical int
}

// byteOffset maps a logical handshake byte to the original wire, skipping
// existing record headers. End positions use byteOffset(size-1)+1 instead.
func (f helloFrame) byteOffset(logical int) int {
	for i := 0; i < f.records.count; i++ {
		r := f.records.at(i)
		n := r.end - r.start - recordHeaderLen
		if logical < n {
			return r.start + recordHeaderLen + logical
		}
		logical -= n
	}
	return f.wireLen
}
func (f helloFrame) handshakeEnd() int { return f.byteOffset(f.size-1) + 1 }

// helloScanner visits each input record once. It copies only the four-byte
// handshake header while incomplete; the logical body is later read in place.
type helloScanner struct {
	records                      helloRecords
	offset, end, payload         int
	header                       [4]byte
	headerN, activeHeaderN, size int
}

func (s *helloScanner) need() int {
	if s.end == 0 {
		return s.offset + recordHeaderLen
	}
	if s.headerN < 4 {
		n := s.offset + recordHeaderLen + s.activeHeaderN + 4 - s.headerN
		if n < s.end {
			return n
		}
	}
	return s.end
}

func (s *helloScanner) scan(wire []byte, limits helloLimits) (helloFrame, error) {
	for {
		if s.end == 0 {
			if s.records.count >= limits.records {
				return helloFrame{}, ErrTooManyClientHelloRecords
			}
			if len(wire) <= s.offset {
				return helloFrame{}, errShort
			}
			if !looksLikeHello(wire[s.offset:]) {
				return helloFrame{}, ErrNotClientHello
			}
			if len(wire)-s.offset < recordHeaderLen {
				return helloFrame{}, errShort
			}
			n, err := recordLen(wire[s.offset:])
			if err != nil {
				return helloFrame{}, err
			}
			s.end = s.offset + n
			if s.end > limits.wireSize() {
				return helloFrame{}, ErrClientHelloTooLarge
			}
			s.records.add(helloRecord{s.offset, s.end})
			s.activeHeaderN = 0
		}
		if s.headerN < 4 {
			available := len(wire)
			if available > s.end {
				available = s.end
			}
			from := s.offset + recordHeaderLen + s.activeHeaderN
			n := available - from
			if n > 4-s.headerN {
				n = 4 - s.headerN
			}
			if n > 0 {
				copy(s.header[s.headerN:], wire[from:from+n])
				s.headerN += n
				s.activeHeaderN += n
			}
			if s.headerN > 0 && s.header[0] != handshakeClientHelo {
				return helloFrame{}, ErrNotClientHello
			}
			if s.headerN == 4 {
				s.size = 4 + (int(s.header[1])<<16 | int(s.header[2])<<8 | int(s.header[3]))
				if s.size > limits.size {
					return helloFrame{}, ErrClientHelloTooLarge
				}
				if s.size < 45 {
					return helloFrame{}, ErrNotClientHello
				}
			}
		}
		if len(wire) < s.end {
			return helloFrame{}, errShort
		}
		s.payload += s.end - s.offset - recordHeaderLen
		s.offset = s.end
		s.end = 0
		if s.size > 0 && s.payload >= s.size {
			f := helloFrame{records: s.records, size: s.size, wireLen: s.offset, sniLogical: -1}
			if err := parseHelloBody(wire, &f); err != nil {
				return helloFrame{}, err
			}
			return f, nil
		}
	}
}

// helloReader walks logical payload without concatenating the records. Its
// limit excludes any coalesced handshake/application bytes after ClientHello.
type helloReader struct {
	wire                       []byte
	records                    helloRecords
	logical, limit, record, at int
}

func (r *helloReader) remaining() int { return r.limit - r.logical }
func (r *helloReader) normalize() {
	for r.at == r.records.at(r.record).end && r.record+1 < r.records.count {
		r.record++
		r.at = r.records.at(r.record).start + recordHeaderLen
	}
}
func (r *helloReader) skip(n int) bool {
	if n < 0 || n > r.remaining() {
		return false
	}
	for n > 0 {
		r.normalize()
		step := r.records.at(r.record).end - r.at
		if step > n {
			step = n
		}
		r.at += step
		r.logical += step
		n -= step
	}
	return true
}
func (r *helloReader) u8() (byte, bool) {
	if r.remaining() < 1 {
		return 0, false
	}
	r.normalize()
	b := r.wire[r.at]
	r.at++
	r.logical++
	return b, true
}
func (r *helloReader) u16() (int, bool) {
	a, ok := r.u8()
	if !ok {
		return 0, false
	}
	b, ok := r.u8()
	return int(a)<<8 | int(b), ok
}
func (r *helloReader) name(n int) string {
	r.normalize()
	if n <= r.records.at(r.record).end-r.at {
		s := string(r.wire[r.at : r.at+n])
		r.at += n
		r.logical += n
		return s
	}
	var b strings.Builder
	b.Grow(n)
	for n > 0 {
		r.normalize()
		step := r.records.at(r.record).end - r.at
		if step > n {
			step = n
		}
		b.Write(r.wire[r.at : r.at+step])
		r.at += step
		r.logical += step
		n -= step
	}
	return b.String()
}
