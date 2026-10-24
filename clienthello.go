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

// errShort means the bytes look like a ClientHello but the record is not
// complete yet.
var errShort = errors.New("desync: incomplete TLS record")

// Hello describes the first TLS record of a connection when it carries a
// ClientHello. Offsets are absolute positions in the bytes that were parsed.
type Hello struct {
	// RecordLen is the full length of the first record, header included.
	RecordLen int
	// SNI is the server name, "" when the hello has none.
	SNI string
	// SNIOffset is where the server name bytes start; -1 without SNI.
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

// ParseHello parses the first TLS record in b as a ClientHello. b must hold the
// whole first record; a ClientHello spread over several records is reported
// without SNI (SNIOffset -1), never misparsed.
func ParseHello(b []byte) (Hello, error) {
	rl, err := recordLen(b)
	if err != nil {
		return Hello{}, err
	}
	if len(b) < rl {
		return Hello{}, errShort
	}
	h := Hello{RecordLen: rl, SNIOffset: -1}

	p := b[recordHeaderLen:rl]
	if len(p) < 4 || p[0] != handshakeClientHelo {
		return Hello{}, ErrNotClientHello
	}
	hsLen := int(p[1])<<16 | int(p[2])<<8 | int(p[3])
	body := p[4:]
	if hsLen < len(body) {
		body = body[:hsLen]
	}
	base := recordHeaderLen + 4 // absolute offset of body[0]

	// legacy_version(2) random(32)
	i := 2 + 32
	// legacy_session_id
	if i+1 > len(body) {
		return h, nil
	}
	i += 1 + int(body[i])
	// cipher_suites
	if i+2 > len(body) {
		return h, nil
	}
	i += 2 + (int(body[i])<<8 | int(body[i+1]))
	// legacy_compression_methods
	if i+1 > len(body) {
		return h, nil
	}
	i += 1 + int(body[i])
	// extensions
	if i+2 > len(body) {
		return h, nil
	}
	extEnd := i + 2 + (int(body[i])<<8 | int(body[i+1]))
	i += 2
	if extEnd > len(body) {
		// The hello continues in a later record: what is here is still valid
		// to walk, it just ends early.
		extEnd = len(body)
	}
	for i+4 <= extEnd {
		typ := int(body[i])<<8 | int(body[i+1])
		l := int(body[i+2])<<8 | int(body[i+3])
		data := i + 4
		if data+l > extEnd {
			return h, nil
		}
		if typ == extServerName {
			name, off := parseServerName(body[data : data+l])
			if off >= 0 {
				h.SNI = name
				h.SNIOffset = base + data + off
			}
			return h, nil
		}
		i = data + l
	}
	return h, nil
}

// parseServerName returns the first host_name entry of a server_name
// extension and its offset inside ext, or -1.
func parseServerName(ext []byte) (string, int) {
	if len(ext) < 2 {
		return "", -1
	}
	listEnd := 2 + (int(ext[0])<<8 | int(ext[1]))
	if listEnd > len(ext) {
		return "", -1
	}
	for i := 2; i+3 <= listEnd; {
		typ := ext[i]
		l := int(ext[i+1])<<8 | int(ext[i+2])
		start := i + 3
		if start+l > listEnd {
			return "", -1
		}
		if typ == sniHostNameType && l > 0 {
			return string(ext[start : start+l]), start
		}
		i = start + l
	}
	return "", -1
}
