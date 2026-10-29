package desync

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// UDPTemplate selects a generated decoy for the UDP burst.
type UDPTemplate int

const (
	// UDPTemplateZero is 64 zero bytes (ByeDPI's UDP fake), the default.
	UDPTemplateZero UDPTemplate = iota
	// UDPTemplateQUICInitial is a QUIC v1 client Initial packet (RFC 9000,
	// RFC 9001): long header, version 1, random 8-byte DCID and SCID, a
	// CRYPTO frame with a TLS ClientHello for UDPOptions.SNI, PADDING to
	// 1200 bytes, payload and header protection with the Initial keys derived
	// from the DCID. An inspecting device that decrypts Initials, as anyone
	// can, reads the decoy's server name. A new packet is generated for every
	// burst.
	UDPTemplateQUICInitial
)

func (t UDPTemplate) String() string {
	switch t {
	case UDPTemplateZero:
		return "zero"
	case UDPTemplateQUICInitial:
		return "quic-initial"
	}
	return fmt.Sprintf("UDPTemplate(%d)", int(t))
}

// DefaultQUICSNI is the decoy server name of the QUIC Initial template when
// UDPOptions.SNI is empty (the server name of the TCP fake template).
const DefaultQUICSNI = "www.wikipedia.org"

// quicInitialSize is the minimum size of a datagram carrying a client
// Initial (RFC 9000 section 14.1); the template has exactly this size.
const quicInitialSize = 1200

const (
	quicVersion1     = 0x00000001
	quicVersion2     = 0x6b3343cf
	quicConnIDLen    = 8
	quicPacketNumLen = 4
	quicTagLen       = 16
	extALPN          = 0x0010
	extQUICTransport = 0x0039
)

// RFC 9001 section 5.2.
var quicV1InitialSalt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

// QUICInitialPayload returns one QUIC v1 Initial decoy of 1200 bytes whose
// ClientHello carries sni (DefaultQUICSNI when empty; ByeDPI wildcards
// '*', '?' and '#' are expanded). Use it as a fixed UDPOptions.Payload;
// UDPOptions.Template = UDPTemplateQUICInitial generates a fresh one per
// burst instead.
func QUICInitialPayload(sni string) ([]byte, error) {
	if sni == "" {
		sni = DefaultQUICSNI
	}
	if err := validFakeSNI(sni); err != nil {
		return nil, err
	}
	return quicInitial(sni)
}

// looksLikeQUICInitial reports whether p is a datagram starting with a QUIC
// v1 (or draft) or v2 client Initial long-header packet of at least 1200
// bytes, the size a client Initial datagram must have.
func looksLikeQUICInitial(p []byte) bool {
	if len(p) < quicInitialSize || p[0]&0xc0 != 0xc0 {
		return false
	}
	typ := p[0] >> 4 & 3
	switch v := binary.BigEndian.Uint32(p[1:5]); {
	case v == quicVersion1 || v&0xffffff00 == 0xff000000:
		if typ != 0 {
			return false
		}
	case v == quicVersion2:
		if typ != 1 {
			return false
		}
	default:
		return false
	}
	return p[5] <= 20
}

func hkdfExtract(salt, secret []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(secret)
	return m.Sum(nil)
}

// hkdfExpandLabel is TLS 1.3's HKDF-Expand-Label with an empty context, for
// outputs of at most one SHA-256 block.
func hkdfExpandLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0, 1) // empty context, then the HKDF counter
	m := hmac.New(sha256.New, secret)
	m.Write(info)
	return m.Sum(nil)[:n]
}

// quicClientInitialKeys derives the client Initial key, IV and header
// protection key from the destination connection ID (RFC 9001 section 5.2).
func quicClientInitialKeys(dcid []byte) (key, iv, hp []byte) {
	client := hkdfExpandLabel(hkdfExtract(quicV1InitialSalt, dcid), "client in", 32)
	return hkdfExpandLabel(client, "quic key", 16), hkdfExpandLabel(client, "quic iv", 12), hkdfExpandLabel(client, "quic hp", 16)
}

func appendQUICVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return binary.BigEndian.AppendUint16(b, uint16(v)|0x4000)
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(b, uint32(v)|0x80000000)
	}
	return binary.BigEndian.AppendUint64(b, v|0xc0<<56)
}

// quicHello is the TLS template's ClientHello adapted to QUIC: the server
// name sni, fresh random values, ALPN h3, QUIC transport parameters with the
// source connection ID, and no padding extension (PADDING frames pad).
func quicHello(sni string, scid []byte) ([]byte, error) {
	h, err := decodeHello(defaultFakeTLS())
	if err != nil {
		return nil, err
	}
	if sni, err = expandFakeSNI(sni); err != nil {
		return nil, err
	}
	h.setSNI(sni)
	if err := h.randomize(); err != nil {
		return nil, err
	}
	h.sessionID = nil // QUIC has no middlebox-compatibility session ID
	exts := h.exts[:0]
	for _, e := range h.exts {
		switch e.typ {
		case extPadding:
			continue
		case extALPN:
			e.data = []byte{0, 3, 2, 'h', '3'}
		}
		exts = append(exts, e)
	}
	// initial_source_connection_id (0x0f) and max_idle_timeout (0x01) = 30 s.
	params := []byte{0x0f, byte(len(scid))}
	params = append(params, scid...)
	params = append(params, 0x01, 4)
	params = appendQUICVarint(params, 30000)
	h.exts = append(exts, tlsExt{typ: extQUICTransport, data: params})
	return h.message(), nil
}

func quicInitial(sni string) ([]byte, error) {
	ids := make([]byte, 2*quicConnIDLen)
	if _, err := crand.Read(ids); err != nil {
		return nil, err
	}
	dcid, scid := ids[:quicConnIDLen], ids[quicConnIDLen:]
	hello, err := quicHello(sni, scid)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 0, 32)
	header = append(header, 0xc0|(quicPacketNumLen-1))
	header = binary.BigEndian.AppendUint32(header, quicVersion1)
	header = append(header, quicConnIDLen)
	header = append(header, dcid...)
	header = append(header, quicConnIDLen)
	header = append(header, scid...)
	header = append(header, 0) // no token
	// Length covers the packet number, the payload and the tag; it is
	// encoded on two bytes, so the header size is known in advance.
	headerLen := len(header) + 2 + quicPacketNumLen
	plainLen := quicInitialSize - headerLen - quicTagLen
	header = binary.BigEndian.AppendUint16(header, uint16(quicPacketNumLen+plainLen+quicTagLen)|0x4000)
	pnOffset := len(header)
	header = append(header, 0, 0, 0, 0) // packet number 0

	plain := make([]byte, 0, plainLen)
	plain = append(plain, 0x06, 0) // CRYPTO frame at offset 0
	plain = appendQUICVarint(plain, uint64(len(hello)))
	plain = append(plain, hello...)
	if len(plain) > plainLen {
		return nil, errors.New("desync: QUIC decoy ClientHello does not fit 1200 bytes")
	}
	plain = plain[:plainLen] // the rest are PADDING frames (zero bytes)

	key, iv, hp := quicClientInitialKeys(dcid)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// The packet number is zero, so the nonce is the IV itself.
	aad := append([]byte(nil), header...)
	packet := aead.Seal(header, iv, plain, aad)
	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], packet[pnOffset+4:pnOffset+4+16])
	packet[0] ^= mask[0] & 0x0f
	for i := 0; i < quicPacketNumLen; i++ {
		packet[pnOffset+i] ^= mask[1+i]
	}
	return packet, nil
}
