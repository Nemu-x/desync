package desync

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func framingRecord(payload []byte) []byte {
	r := []byte{22, 3, 3, byte(len(payload) >> 8), byte(len(payload))}
	return append(r, payload...)
}

func TestRecordVersionsAndPartialInputCounts(t *testing.T) {
	rec := framingHello("fragment.example", 0)
	h, _ := ParseHello(rec)
	wire := reframeInput(rec, h.SNIOffset-5+2)
	wire[2] = 1 // An initial ClientHello record may use legacy version 0x0301.
	for _, buffered := range []int{0, 7} {
		cut := h.SNIOffset + 1
		for _, tc := range []struct{ wire, logical int }{{cut + 2, cut}, {cut + 5, cut}, {cut + 7, cut + 2}} {
			raw := lifecycleStream(t)
			raw.failCall, raw.failAfter = 1, tc.wire
			w := WrapConn(raw, Options{TLSRec: []Pos{{Offset: 1, FromSNI: true}}})
			if buffered > 0 {
				if _, err := w.Write(wire[:buffered]); err != nil {
					t.Fatal(err)
				}
			}
			n, err := w.Write(wire[buffered:])
			if n != tc.logical-buffered || !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("buffered=%d partial count=%d want=%d error=%v", buffered, n, tc.logical-buffered, err)
			}
		}
	}
	raw := lifecycleStream(t)
	w := WrapConn(raw, Options{TLSRec: []Pos{{Offset: 1, FromSNI: true}}})
	defer w.Close()
	if _, err := w.Write(wire); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(framingPayload(t, raw.data), rec[5:]) {
		t.Fatal("handshake changed while preserving versions")
	}
	// This cut is before the original boundary, so the first record's two
	// pieces retain 0x0301 and the untouched second record retains 0x0303.
	rs := records(t, raw.data)
	if len(rs) != 3 || rs[0][2] != 1 || rs[1][2] != 1 || rs[2][2] != 3 {
		t.Fatal("input record versions changed")
	}
}

func TestHandshakeLengthExcludesTrailingSNI(t *testing.T) {
	rec := framingHello("fragment.example", 0)
	rec[6], rec[7], rec[8] = 0, 0, 41 // Minimal TLS 1.2 body without extensions.
	h, err := ParseHello(rec)
	if err != nil || h.SNI != "" || h.SNIOffset != -1 {
		t.Fatalf("SNI invented from trailing bytes: %+v %v", h, err)
	}
	raw := lifecycleStream(t)
	w := WrapConn(raw, Options{TLSRec: []Pos{{Offset: 1, FromSNI: true}}})
	defer w.Close()
	if _, err := w.Write(rec); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw.data, rec) {
		t.Fatal("trailing SNI transformed a hello without extensions")
	}
}

func TestEarlyServerDisconnectDuringAssembly(t *testing.T) {
	a, peer := net.Pipe()
	defer peer.Close()
	w := WrapConn(a, boundedHelloOptions(nil))
	defer w.Close()
	rec := framingHello("fragment.example", 0)
	if _, err := w.Write(rec[:1]); err != nil {
		t.Fatal(err)
	}
	peer.Close()
	done := make(chan error, 1)
	go func() { _, err := w.Read(make([]byte, 1)); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server EOF was blocked by assembly")
	}
	if _, err := w.Write(rec[1:]); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("early disconnect hidden: %v", err)
	}
}

func framingHello(host string, padding int) []byte {
	name := append([]byte{0, byte(len(host) + 3), 0, byte(len(host) >> 8), byte(len(host))}, host...)
	ext := append([]byte{0, 0, byte(len(name) >> 8), byte(len(name))}, name...)
	if padding > 0 {
		ext = append(ext, 0, 21, byte(padding>>8), byte(padding))
		ext = append(ext, make([]byte, padding)...)
	}
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return framingRecord(hs)
}

// reframeInput changes only the input record boundaries, not handshake bytes.
func reframeInput(rec []byte, cuts ...int) []byte {
	payload := rec[5:]
	var out []byte
	start := 0
	for _, end := range append(cuts, len(payload)) {
		piece := framingRecord(payload[start:end])
		copy(piece[:3], rec[:3])
		out = append(out, piece...)
		start = end
	}
	return out
}

func framingPayload(t *testing.T, wire []byte) []byte {
	t.Helper()
	var payload []byte
	for _, r := range records(t, wire) {
		if len(r) == 5 || len(r)-5 > maxRecordPayload {
			t.Fatal("invalid generated record length")
		}
		payload = append(payload, r[5:]...)
	}
	return payload
}

func TestParseHelloAcrossEveryRecordBoundary(t *testing.T) {
	rec := framingHello("fragment.example", 0)
	want, _ := ParseHello(rec)
	for cut := 1; cut < len(rec)-5; cut++ {
		wire := reframeInput(rec, cut)
		h, err := ParseHello(wire)
		if err != nil || h.SNI != want.SNI || h.RecordLen != 5+cut {
			t.Fatalf("cut=%d: %+v %v", cut, h, err)
		}
		offset := want.SNIOffset
		if cut <= offset-5 {
			offset += 5
		}
		if h.SNIOffset != offset {
			t.Fatalf("cut=%d: SNI start=%d want=%d", cut, h.SNIOffset, offset)
		}
		if _, err = ParseHello(wire[:5+cut]); !errors.Is(err, errShort) {
			t.Fatalf("incomplete handshake cut=%d accepted: %v", cut, err)
		}
	}
}

func TestMultiRecordTransformAndTrailingBytes(t *testing.T) {
	rec := framingHello("fragment.example", 0)
	h, _ := ParseHello(rec)
	// Split the handshake header and the hostname itself across records.
	wire := reframeInput(rec, 1, 2, 3, h.SNIOffset-5+2)
	tail := append(framingRecord([]byte{0, 0, 0, 0}), []byte("opaque trailing bytes")...)
	for _, chunk := range []int{1, 7, len(wire) + len(tail)} {
		raw := lifecycleStream(t)
		w := WrapConn(raw, Options{TLSRec: []Pos{{Offset: 1, FromSNI: true}}, Split: []Pos{{Offset: 3, FromSNI: true}}})
		input := append(append([]byte(nil), wire...), tail...)
		for at := 0; at < len(input); {
			end := at + chunk
			if end > len(input) {
				end = len(input)
			}
			part := append([]byte(nil), input[at:end]...)
			if n, err := w.Write(part); n != len(part) || err != nil {
				t.Fatalf("chunk=%d: %d %v", chunk, n, err)
			}
			for i := range part {
				part[i] = 0xff
			}
			at = end
		}
		end := len(wire) + 5 // Exactly one new record boundary inside the SNI.
		if len(raw.data) < end || !bytes.Equal(framingPayload(t, raw.data[:end]), rec[5:]) {
			t.Fatalf("chunk=%d: handshake bytes changed", chunk)
		}
		if !bytes.Equal(raw.data[end:], tail) {
			t.Fatalf("chunk=%d: trailing bytes changed", chunk)
		}
		if raw.calls < 2 {
			t.Fatal("configured TCP split was lost")
		}
		w.Close()
	}
}

func TestCoalescedHandshakeTailDoesNotBecomeClientHello(t *testing.T) {
	rec := framingHello("fragment.example", 0)
	tail := []byte{0x0b, 0, 0, 2, 0xaa, 0xbb}
	coalesced := framingRecord(append(append([]byte(nil), rec[5:]...), tail...))
	raw := lifecycleStream(t)
	// Absolute cut after the logical ClientHello must not touch its tail.
	w := WrapConn(raw, Options{TLSRec: []Pos{{Offset: 1, FromSNI: true}, {Offset: len(rec) + 2}}})
	defer w.Close()
	if _, err := w.Write(coalesced); err != nil {
		t.Fatal(err)
	}
	if got := len(records(t, raw.data)); got != 2 {
		t.Fatalf("tail caused an extra cut: records=%d", got)
	}
	if !bytes.Equal(framingPayload(t, raw.data), coalesced[5:]) {
		t.Fatal("coalesced handshake tail changed")
	}
}

func TestMalformedVectorsAreNotTransformed(t *testing.T) {
	valid := framingHello("fragment.example", 0)
	bad := append([]byte(nil), valid...)
	// The SNI extension is followed by a truncated extension header. Earlier
	// parsing returned the hostname without validating the rest of the hello.
	bad = append(bad, 0xff)
	binary.BigEndian.PutUint16(bad[3:5], uint16(len(bad)-5))
	bad[8]++ // handshake size
	// extensions length follows the fixed test fields at wire offset 50.
	binary.BigEndian.PutUint16(bad[50:52], uint16(len(bad)-52))
	if _, err := ParseHello(bad); !errors.Is(err, ErrNotClientHello) {
		t.Fatalf("malformed extensions accepted: %v", err)
	}
	for _, p := range [][]byte{bad, []byte("GET / HTTP/1.1\r\n\r\n"), {22, 3, 3, 0, 0}, {22, 3, 3, 0xff, 0xff}} {
		raw := lifecycleStream(t)
		w := WrapConn(raw, Options{TLSRec: []Pos{{Offset: 12}}})
		for _, b := range p {
			if _, err := w.Write([]byte{b}); err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(raw.data, p) {
			t.Fatal("malformed/non-TLS input changed")
		}
		w.Close()
	}
}
