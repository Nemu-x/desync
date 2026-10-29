package desync

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

// RFC 9001 appendix A.1.
func TestQUICInitialKeysRFC9001(t *testing.T) {
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	key, iv, hp := quicClientInitialKeys(dcid)
	for name, got := range map[string][]byte{"1f369613dd76d5467730efcbe3b1a22d": key, "fa044b2f42a3fd3b46fb255c": iv, "9f50449e04a0e810283a1e9933adedd2": hp} {
		if hex.EncodeToString(got) != name {
			t.Fatalf("got %x, want %s", got, name)
		}
	}
}

// openQUICInitial removes header protection, decrypts the packet and returns
// the header fields and the CRYPTO frame data.
func openQUICInitial(t *testing.T, p []byte) (dcid, scid, crypto []byte) {
	t.Helper()
	if len(p) != 1200 || p[0]&0xf0 != 0xc0 || binary.BigEndian.Uint32(p[1:5]) != 1 {
		t.Fatalf("not a v1 Initial: % x", p[:8])
	}
	at := 5
	dcid = p[at+1 : at+1+int(p[at])]
	at += 1 + len(dcid)
	scid = p[at+1 : at+1+int(p[at])]
	at += 1 + len(scid)
	if p[at] != 0 { // token length
		t.Fatal("token present")
	}
	at++
	length := int(binary.BigEndian.Uint16(p[at:]) & 0x3fff)
	at += 2
	if at+length != len(p) {
		t.Fatalf("Length %d does not end the datagram", length)
	}
	key, iv, hp := quicClientInitialKeys(dcid)
	block, _ := aes.NewCipher(hp)
	var mask [16]byte
	block.Encrypt(mask[:], p[at+4:at+20])
	header := append([]byte(nil), p[:at+4]...)
	header[0] ^= mask[0] & 0x0f
	pnLen := int(header[0]&3) + 1
	if pnLen != 4 {
		t.Fatalf("packet number length %d", pnLen)
	}
	for i := 0; i < pnLen; i++ {
		header[at+i] ^= mask[1+i]
	}
	pn := binary.BigEndian.Uint32(header[at:])
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 4; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	kb, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(kb)
	plain, err := aead.Open(nil, nonce, p[at+4:], header)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if plain[0] != 0x06 || plain[1] != 0 {
		t.Fatalf("no CRYPTO frame at offset 0: % x", plain[:4])
	}
	n := int(binary.BigEndian.Uint16(plain[2:]) & 0x3fff)
	crypto = plain[4 : 4+n]
	for _, b := range plain[4+n:] {
		if b != 0 {
			t.Fatal("padding is not PADDING frames")
		}
	}
	return dcid, scid, crypto
}

func TestQUICInitialPayload(t *testing.T) {
	seen := map[string]bool{}
	for _, sni := range []string{"", "quic.example", "q#.example"} {
		p, err := QUICInitialPayload(sni)
		if err != nil {
			t.Fatal(err)
		}
		if !looksLikeQUICInitial(p) {
			t.Fatal("the template does not look like a QUIC Initial")
		}
		dcid, scid, crypto := openQUICInitial(t, p)
		if len(dcid) != 8 || len(scid) != 8 || seen[string(dcid)] {
			t.Fatalf("connection IDs %x %x", dcid, scid)
		}
		seen[string(dcid)] = true
		// Frame the handshake message as a record to parse it.
		rec := append([]byte{0x16, 3, 1, byte(len(crypto) >> 8), byte(len(crypto))}, crypto...)
		h := mustParse(t, rec)
		want := sni
		switch sni {
		case "":
			want = DefaultQUICSNI
		case "q#.example":
			if len(h.SNI) != len(sni) || h.SNI[1] < '0' || h.SNI[1] > '9' {
				t.Fatalf("wildcard SNI %q", h.SNI)
			}
			want = h.SNI
		}
		if h.SNI != want {
			t.Fatalf("SNI %q, want %q", h.SNI, want)
		}
		hello, err := decodeHello(rec)
		if err != nil {
			t.Fatal(err)
		}
		if i := hello.ext(extALPN); i < 0 || !bytes.Equal(hello.exts[i].data, []byte{0, 3, 2, 'h', '3'}) {
			t.Fatal("ALPN is not h3")
		}
		if i := hello.ext(extQUICTransport); i < 0 || !bytes.Contains(hello.exts[i].data, append([]byte{0x0f, 8}, scid...)) {
			t.Fatal("transport parameters lack initial_source_connection_id")
		}
		if hello.ext(extPadding) >= 0 || len(hello.sessionID) != 0 {
			t.Fatal("TLS padding or session ID inside QUIC")
		}
	}
	if _, err := QUICInitialPayload("bad_name"); err == nil {
		t.Fatal("bad SNI accepted")
	}
}

func TestLooksLikeQUICInitial(t *testing.T) {
	p, _ := QUICInitialPayload("")
	mk := func(first byte, version uint32, size int) []byte {
		b := make([]byte, size)
		b[0] = first
		binary.BigEndian.PutUint32(b[1:], version)
		b[5] = 8
		return b
	}
	for name, c := range map[string]struct {
		p    []byte
		want bool
	}{
		"template":      {p, true},
		"v1 initial":    {mk(0xc3, 1, 1250), true},
		"draft-29":      {mk(0xc0, 0xff00001d, 1200), true},
		"v2 initial":    {mk(0xd0, quicVersion2, 1200), true},
		"v2 type 0":     {mk(0xc0, quicVersion2, 1200), false},
		"v1 handshake":  {mk(0xe0, 1, 1200), false},
		"short header":  {mk(0x40, 1, 1200), false},
		"no fixed bit":  {mk(0x80, 1, 1200), false},
		"too small":     {mk(0xc0, 1, 1199), false},
		"negotiation":   {mk(0xc0, 0, 1200), false},
		"unknown":       {mk(0xc0, 0x0a0a0a0a, 1200), false},
		"zeros":         {make([]byte, 64), false},
		"dns":           {[]byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}, false},
		"oversized cid": {func() []byte { b := mk(0xc0, 1, 1200); b[5] = 21; return b }(), false},
	} {
		if got := looksLikeQUICInitial(c.p); got != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestUDPTemplateValidation(t *testing.T) {
	for name, o := range map[string]UDPOptions{
		"unknown template":     {TTL: 4, Template: 7},
		"template and payload": {TTL: 4, Template: UDPTemplateQUICInitial, Payload: []byte{1}},
		"sni without template": {TTL: 4, SNI: "a.example"},
		"bad sni":              {TTL: 4, Template: UDPTemplateQUICInitial, SNI: "1.2.3.4"},
	} {
		if err := o.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := (UDPOptions{TTL: 4, Template: UDPTemplateQUICInitial, SNI: "a.example", QUICOnly: true}).Validate(); SupportsUDPFake() && err != nil {
		t.Fatal(err)
	}
	if UDPTemplateQUICInitial.String() != "quic-initial" || UDPTemplateZero.String() != "zero" {
		t.Fatal("template names")
	}
}

// QUICOnly leaves datagrams that are not QUIC Initials untouched, and the
// QUIC template's decoys precede the original.
func TestUDPQUICOnlyAndTemplate(t *testing.T) {
	if !SupportsUDPFake() {
		t.Skip("no UDP fake")
	}
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	counters := &UDPCounters{}
	pc, err := WrapPacketConn(client, UDPOptions{TTL: 64, Repeats: 2, Packets: 1, Template: UDPTemplateQUICInitial, SNI: "decoy.example", QUICOnly: true, Counters: counters})
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	defer pc.Close()
	read := func() []byte {
		_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 2048)
		n, _, err := server.ReadFrom(b)
		if err != nil {
			t.Fatal(err)
		}
		return b[:n]
	}
	dns := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	quic := make([]byte, 1250)
	quic[0] = 0xc3
	binary.BigEndian.PutUint32(quic[1:], 1)
	for _, p := range [][]byte{dns, dns, quic, quic} {
		if _, err := pc.WriteTo(p, server.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	// Two DNS datagrams untouched; before the first QUIC Initial two
	// decoys; the second QUIC Initial is past Packets.
	if got := read(); !bytes.Equal(got, dns) {
		t.Fatalf("first datagram %d bytes", len(got))
	}
	if got := read(); !bytes.Equal(got, dns) {
		t.Fatalf("second datagram %d bytes", len(got))
	}
	var dcids [][]byte
	for i := 0; i < 2; i++ {
		dcid, _, _ := openQUICInitial(t, read())
		dcids = append(dcids, dcid)
	}
	if !bytes.Equal(dcids[0], dcids[1]) {
		t.Fatal("one burst used two decoys")
	}
	for i := 0; i < 2; i++ {
		if got := read(); !bytes.Equal(got, quic) {
			t.Fatalf("QUIC datagram %d changed", i)
		}
	}
	if s := counters.Snapshot(); s.Packets != 4 || s.FakePackets != 2 || s.Peers != 1 {
		t.Fatalf("counters %+v", s)
	}
}
