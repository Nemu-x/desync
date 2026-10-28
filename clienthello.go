package desync

import "errors"

// TLS record and handshake constants used to recognise a ClientHello.
const (
	recordHeaderLen     = 5
	recordTypeHandshake = 0x16
	handshakeClientHelo = 0x01
	extServerName       = 0x0000
	sniHostNameType     = 0x00
	maxRecordPayload    = 1 << 14 // TLS plaintext record limit
)

// ErrNotClientHello means the bytes are not the start of a TLS ClientHello.
var ErrNotClientHello = errors.New("desync: not a TLS ClientHello")

// ErrIncompleteClientHello means that record framing or the complete first
// ClientHello handshake needs more bytes. It is not a successful missing SNI.
var ErrIncompleteClientHello = errors.New("desync: incomplete TLS ClientHello")

var errShort = ErrIncompleteClientHello

// Hello describes the first complete ClientHello. Offsets refer to original
// wire bytes, including any existing TLS record headers.
type Hello struct {
	// RecordLen is the full length of the first record, header included.
	RecordLen int
	// SNI is the server name, "" when the hello has none.
	SNI string
	// SNIOffset is where the server name starts; -1 without SNI. The name can
	// cross record headers, so use SNI rather than slicing contiguous wire bytes.
	SNIOffset int
}

// looksLikeHello reports whether b can be the start of a TLS handshake record.
// It needs only the first byte or two, so a caller can decide early whether to
// buffer for a full record.
func looksLikeHello(b []byte) bool {
	if len(b) == 0 || b[0] != recordTypeHandshake {
		return false
	}
	// Record version major is 3 for every SSL3/TLS version.
	return len(b) < 2 || b[1] == 3
}

// recordLen returns the full length of the first record (header included), or
// errShort if the header itself is incomplete.
func recordLen(b []byte) (int, error) {
	if !looksLikeHello(b) {
		return 0, ErrNotClientHello
	}
	if len(b) < recordHeaderLen {
		return 0, errShort
	}
	n := int(b[3])<<8 | int(b[4])
	if n == 0 || n > maxRecordPayload {
		return 0, ErrNotClientHello
	}
	return recordHeaderLen + n, nil
}

// ParseHello parses a complete ClientHello across consecutive TLS records.
// It uses default size/record limits, ignores bytes after its final record,
// and returns ErrIncompleteClientHello if the handshake is not complete.
// RecordLen remains the length of the first input record for compatibility.
func ParseHello(b []byte) (Hello, error) {
	var s helloScanner
	f, err := s.scan(b, (*ClientHelloOptions)(nil).limits())
	return f.hello, err
}

func parseHelloBody(wire []byte, f *helloFrame) error {
	f.hello = Hello{RecordLen: f.records.first.end, SNIOffset: -1}
	r := helloReader{wire: wire, records: f.records, limit: f.size, at: recordHeaderLen}
	if !r.skip(4 + 2 + 32) {
		return ErrNotClientHello
	}
	session, ok := r.u8()
	if !ok || session > 32 || !r.skip(int(session)) {
		return ErrNotClientHello
	}
	suites, ok := r.u16()
	if !ok || suites < 2 || suites%2 != 0 || !r.skip(suites) {
		return ErrNotClientHello
	}
	compression, ok := r.u8()
	if !ok || compression == 0 || !r.skip(int(compression)) {
		return ErrNotClientHello
	}
	if r.remaining() == 0 {
		return nil
	} // TLS 1.2 may omit the extension vector.
	extensions, ok := r.u16()
	if !ok || extensions != r.remaining() {
		return ErrNotClientHello
	}
	seenSNI := false
	for r.remaining() > 0 {
		typ, ok := r.u16()
		if !ok {
			return ErrNotClientHello
		}
		n, ok := r.u16()
		if !ok || n > r.remaining() {
			return ErrNotClientHello
		}
		if typ != extServerName {
			r.skip(n)
			continue
		}
		if seenSNI {
			return ErrNotClientHello
		}
		seenSNI = true
		end := r.logical + n
		list, ok := r.u16()
		if !ok || list == 0 || r.logical+list != end {
			return ErrNotClientHello
		}
		for r.logical < end {
			if end-r.logical < 3 {
				return ErrNotClientHello
			}
			kind, _ := r.u8()
			size, _ := r.u16()
			if size == 0 || size > end-r.logical {
				return ErrNotClientHello
			}
			if kind == sniHostNameType {
				if f.hello.SNIOffset >= 0 {
					return ErrNotClientHello
				}
				r.normalize()
				f.sniLogical = r.logical
				f.hello.SNIOffset = r.at
				f.hello.SNI = r.name(size)
			} else {
				r.skip(size)
			}
		}
	}
	return nil
}
