package desync

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// The decoy ClientHello builder behind FakeOptions.SNI, FromOriginal and
// Randomize. It follows the options of ByeDPI v0.17.3 (--fake-sni and
// --fake-tls-mod rand/orig, packets.c change_tls_sni, randomize_tls and
// copy_name; MIT, see third_party/BYEDPI-LICENSE), reimplemented by parsing
// and re-encoding the handshake, so every length is recomputed.

const (
	extPadding  = 0x0015
	extKeyShare = 0x0033
	// maxFakeSNI bounds FakeOptions.SNI; one name is drawn per connection.
	maxFakeSNI = 64
	// maxFakeOffset bounds FakeOptions.Offset (a decoy is at most one
	// ClientHello plus padding).
	maxFakeOffset = 1 << 16
)

var errBadDecoyHello = errors.New("desync: fake payload is not a TLS ClientHello")

// tlsExt is one ClientHello extension; data excludes type and length.
type tlsExt struct {
	typ  uint16
	data []byte
}

// tlsHello is a parsed ClientHello handshake message.
type tlsHello struct {
	record      [3]byte // content type and record version used to re-frame it
	version     [2]byte
	random      [32]byte
	sessionID   []byte
	suites      []byte
	compression []byte
	exts        []tlsExt
	hasExts     bool // TLS 1.2 may omit the extension vector
}

type byteReader struct {
	b  []byte
	ok bool
}

func (r *byteReader) take(n int) []byte {
	if !r.ok || n < 0 || n > len(r.b) {
		r.ok = false
		return nil
	}
	v := r.b[:n:n]
	r.b = r.b[n:]
	return v
}

func (r *byteReader) u8() int {
	v := r.take(1)
	if v == nil {
		return 0
	}
	return int(v[0])
}

func (r *byteReader) u16() int {
	v := r.take(2)
	if v == nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(v))
}

// decodeHello parses the handshake message of a complete ClientHello given
// as wire bytes (one or more records). The result references fresh copies.
func decodeHello(wire []byte) (*tlsHello, error) {
	var s helloScanner
	frame, err := s.scan(wire, (*ClientHelloOptions)(nil).limits())
	if err != nil {
		return nil, err
	}
	return decodeHelloFrame(wire, frame)
}

// decodeHelloFrame parses the hello described by frame inside wire.
func decodeHelloFrame(wire []byte, frame helloFrame) (*tlsHello, error) {
	msg := make([]byte, 0, frame.size)
	for i := 0; i < frame.records.count && len(msg) < frame.size; i++ {
		r := frame.records.at(i)
		part := wire[r.start+recordHeaderLen : r.end]
		if n := frame.size - len(msg); len(part) > n {
			part = part[:n]
		}
		msg = append(msg, part...)
	}
	if len(msg) != frame.size || len(msg) < 4 || msg[0] != handshakeClientHelo {
		return nil, errBadDecoyHello
	}
	h := &tlsHello{}
	copy(h.record[:], wire[:3])
	r := byteReader{b: msg[4:], ok: true}
	copy(h.version[:], r.take(2))
	copy(h.random[:], r.take(32))
	h.sessionID = r.take(r.u8())
	h.suites = r.take(r.u16())
	h.compression = r.take(r.u8())
	if !r.ok || len(h.sessionID) > 32 || len(h.suites) < 2 || len(h.suites)%2 != 0 || len(h.compression) == 0 {
		return nil, errBadDecoyHello
	}
	if len(r.b) == 0 {
		return h, nil
	}
	h.hasExts = true
	extBytes := r.take(r.u16())
	exts := byteReader{b: extBytes, ok: r.ok}
	if !r.ok || len(r.b) != 0 {
		return nil, errBadDecoyHello
	}
	for len(exts.b) > 0 {
		typ := uint16(exts.u16())
		data := exts.take(exts.u16())
		if !exts.ok {
			return nil, errBadDecoyHello
		}
		h.exts = append(h.exts, tlsExt{typ: typ, data: data})
	}
	return h, nil
}

func (h *tlsHello) ext(typ uint16) int {
	for i, e := range h.exts {
		if e.typ == typ {
			return i
		}
	}
	return -1
}

// size is the length of the handshake message, its 4-byte header included.
func (h *tlsHello) size() int {
	n := 4 + 2 + 32 + 1 + len(h.sessionID) + 2 + len(h.suites) + 1 + len(h.compression)
	if h.hasExts {
		n += 2
		for _, e := range h.exts {
			n += 4 + len(e.data)
		}
	}
	return n
}

// message encodes the handshake message with every length recomputed.
func (h *tlsHello) message() []byte {
	n := h.size()
	b := make([]byte, 0, n)
	b = append(b, handshakeClientHelo, byte((n-4)>>16), byte((n-4)>>8), byte(n-4))
	b = append(b, h.version[:]...)
	b = append(b, h.random[:]...)
	b = append(b, byte(len(h.sessionID)))
	b = append(b, h.sessionID...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(h.suites)))
	b = append(b, h.suites...)
	b = append(b, byte(len(h.compression)))
	b = append(b, h.compression...)
	if h.hasExts {
		total := 0
		for _, e := range h.exts {
			total += 4 + len(e.data)
		}
		b = binary.BigEndian.AppendUint16(b, uint16(total))
		for _, e := range h.exts {
			b = binary.BigEndian.AppendUint16(b, e.typ)
			b = binary.BigEndian.AppendUint16(b, uint16(len(e.data)))
			b = append(b, e.data...)
		}
	}
	return b
}

// wire frames the handshake message in TLS records of at most 16 KiB.
func (h *tlsHello) wire() []byte {
	msg := h.message()
	out := make([]byte, 0, len(msg)+recordHeaderLen*(1+len(msg)/maxRecordPayload))
	for len(msg) > 0 {
		n := len(msg)
		if n > maxRecordPayload {
			n = maxRecordPayload
		}
		out = append(out, h.record[0], h.record[1], h.record[2], byte(n>>8), byte(n))
		out = append(out, msg[:n]...)
		msg = msg[n:]
	}
	return out
}

// setSNI replaces (or, when missing, prepends) the server_name extension.
// A padding extension absorbs the size change where it can, so a template
// keeps its length. The result can exceed 16 bits only for absurd inputs,
// which validation rules out.
func (h *tlsHello) setSNI(name string) {
	before := h.size()
	data := make([]byte, 0, 5+len(name))
	data = binary.BigEndian.AppendUint16(data, uint16(len(name)+3))
	data = append(data, sniHostNameType)
	data = binary.BigEndian.AppendUint16(data, uint16(len(name)))
	data = append(data, name...)
	h.hasExts = true
	if i := h.ext(extServerName); i >= 0 {
		h.exts[i].data = data
	} else {
		h.exts = append([]tlsExt{{typ: extServerName, data: data}}, h.exts...)
	}
	if i := h.ext(extPadding); i >= 0 {
		if n := len(h.exts[i].data) - (h.size() - before); n >= 0 {
			h.exts[i].data = make([]byte, n)
		}
	}
}

// randomize replaces the random, the session ID and the key share values
// (ByeDPI randomize_tls). Lengths are unchanged.
func (h *tlsHello) randomize() error {
	if _, err := crand.Read(h.random[:]); err != nil {
		return err
	}
	sid := make([]byte, len(h.sessionID))
	if _, err := crand.Read(sid); err != nil {
		return err
	}
	h.sessionID = sid
	i := h.ext(extKeyShare)
	if i < 0 {
		return nil
	}
	data := append([]byte(nil), h.exts[i].data...)
	r := byteReader{b: data, ok: true}
	shares := r.take(r.u16())
	list := byteReader{b: shares, ok: r.ok}
	for len(list.b) > 0 {
		list.take(2) // group
		key := list.take(list.u16())
		if !list.ok {
			break // malformed shares stay as they were
		}
		if _, err := crand.Read(key); err != nil {
			return err
		}
	}
	h.exts[i].data = data
	return nil
}

// expandFakeSNI replaces ByeDPI's wildcards: '*' a random lower-case letter
// or digit, '?' a random letter, '#' a random digit.
func expandFakeSNI(name string) (string, error) {
	if !strings.ContainsAny(name, "*?#") {
		return name, nil
	}
	random := make([]byte, len(name))
	if _, err := crand.Read(random); err != nil {
		return "", err
	}
	const letters, digits = "abcdefghijklmnopqrstuvwxyz", "0123456789"
	b := []byte(name)
	for i, c := range b {
		switch c {
		case '*':
			b[i] = (digits + letters)[int(random[i])%36]
		case '?':
			b[i] = letters[int(random[i])%26]
		case '#':
			b[i] = digits[int(random[i])%10]
		}
	}
	return string(b), nil
}

// validFakeSNI checks a decoy server name as a DNS host name (RFC 1123
// letters, digits and hyphens; wildcards count as letters). IP literals are
// rejected: RFC 6066 does not allow them in server_name.
func validFakeSNI(name string) error {
	if name == "" || len(name) > 253 {
		return fmt.Errorf("desync: fake SNI %q must be 1 to 253 bytes", name)
	}
	if net.ParseIP(name) != nil {
		return fmt.Errorf("desync: fake SNI %q is an IP address", name)
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("desync: fake SNI %q has an empty or over-long label", name)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("desync: fake SNI %q has a label starting or ending with '-'", name)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '*' || c == '?' || c == '#') {
				return fmt.Errorf("desync: fake SNI %q contains %q", name, c)
			}
		}
	}
	return nil
}

// modifiesHello reports whether the decoy is built per connection.
func (f *FakeOptions) modifiesHello() bool {
	return len(f.SNI) > 0 || f.FromOriginal || f.Randomize
}

func (f *FakeOptions) validateDecoy() error {
	if f.Offset < 0 || f.Offset >= maxFakeOffset {
		return fmt.Errorf("desync: fake offset must be between 0 and %d", maxFakeOffset-1)
	}
	if len(f.SNI) > maxFakeSNI {
		return fmt.Errorf("desync: at most %d fake SNI names", maxFakeSNI)
	}
	for _, name := range f.SNI {
		if err := validFakeSNI(name); err != nil {
			return err
		}
	}
	if f.FromOriginal {
		if len(f.Payload) > 0 {
			return fmt.Errorf("desync: fake FromOriginal and Payload are mutually exclusive")
		}
		if len(f.SNI) == 0 && !f.Randomize {
			return fmt.Errorf("desync: fake FromOriginal needs SNI or Randomize, otherwise the decoy equals the original")
		}
		return nil
	}
	if f.modifiesHello() && len(f.Payload) > 0 {
		if _, err := decodeHello(f.Payload); err != nil {
			return fmt.Errorf("desync: fake SNI/Randomize need a ClientHello payload: %w", err)
		}
	}
	return nil
}

// fakeDecoy returns the decoy bytes for this connection: Payload or the
// template, or, with SNI/FromOriginal/Randomize, a ClientHello rebuilt from
// them (or from the connection's own hello in rec) with valid lengths.
func (c *Conn) fakeDecoy(rec []byte, frame helloFrame) ([]byte, error) {
	f := c.opts.Fake
	base := f.Payload
	if len(base) == 0 {
		base = defaultFakeTLS()
	}
	if !f.modifiesHello() {
		return base, nil
	}
	var h *tlsHello
	var err error
	if f.FromOriginal {
		h, err = decodeHelloFrame(rec, frame)
	} else {
		h, err = decodeHello(base)
	}
	if err != nil {
		return nil, fmt.Errorf("desync: build fake ClientHello: %w", err)
	}
	if len(f.SNI) > 0 {
		name := f.SNI[0]
		if len(f.SNI) > 1 {
			var b [4]byte
			if _, err := crand.Read(b[:]); err != nil {
				return nil, err
			}
			name = f.SNI[binary.LittleEndian.Uint32(b[:])%uint32(len(f.SNI))]
		}
		if name, err = expandFakeSNI(name); err != nil {
			return nil, err
		}
		h.setSNI(name)
	}
	if f.Randomize {
		if err := h.randomize(); err != nil {
			return nil, err
		}
	}
	return h.wire(), nil
}

// fakeBytes is the first transmission of a piece of size bytes: the decoy
// from offset on, zero-padded or truncated.
func fakeBytes(decoy []byte, offset, size int) []byte {
	out := make([]byte, size)
	if offset < len(decoy) {
		copy(out, decoy[offset:])
	}
	return out
}
