package desync

import (
	"bytes"
	"testing"
)

func FuzzClientHelloFraming(f *testing.F) {
	valid := framingHello("fragment.example", 0)
	for _, p := range [][]byte{valid, reframeInput(valid, 1, 2, 3, 61), valid[:8], {22, 3, 3, 0, 0}, []byte("GET / HTTP/1.1\r\n\r\n"), framingHello("fragment.example", 8000)} {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		var scanner helloScanner
		frame, err := scanner.scan(wire, (*ClientHelloOptions)(nil).limits())
		if err != nil {
			return
		}
		h := frame.hello
		if frame.wireLen > len(wire) || frame.size > DefaultMaxClientHelloSize || frame.records.count > DefaultMaxClientHelloRecords {
			t.Fatal("parser exceeded bounds")
		}
		if h.SNIOffset >= len(wire) || (h.SNI == "" && h.SNIOffset != -1) {
			t.Fatal("invalid SNI metadata")
		}
		// Compare independent payload flattening before/after transformation;
		// generated record headers must never change the logical handshake.
		cuts := frame.cuts([]Pos{{Offset: 1, FromSNI: true}, {Offset: -1, FromSNI: true}, {Offset: 12}, {Offset: 12}, {Offset: frame.wireLen + 1}}, true)
		out := fragmentHello(wire[:frame.wireLen], frame, cuts)
		if !bytes.Equal(framingPayload(t, out), framingPayload(t, wire[:frame.wireLen])) {
			t.Fatal("transformation changed logical bytes")
		}
		if !bytes.Equal(framingSNIBytes(wire, frame), []byte(h.SNI)) {
			t.Fatal("SNI bytes do not match input")
		}
	})
}

// The fuzz oracle reads the input payload independently of the scatter reader.
func framingSNIBytes(wire []byte, frame helloFrame) []byte {
	h := frame.hello
	if h.SNIOffset < 0 {
		return nil
	}
	var out []byte
	start := h.SNIOffset
	for i := 0; i < frame.records.count && len(out) < len(h.SNI); i++ {
		r := frame.records.at(i)
		if start >= r.end {
			continue
		}
		if start < r.start+5 {
			start = r.start + 5
		}
		end := start + len(h.SNI) - len(out)
		if end > r.end {
			end = r.end
		}
		out = append(out, wire[start:end]...)
		start = r.end
	}
	return out
}

func FuzzClientHelloAssembly(f *testing.F) {
	valid := framingHello("fragment.example", 0)
	for _, p := range [][]byte{valid, reframeInput(valid, 1, 2, 3, 61), valid[:8], {22, 3, 3, 0, 0}, []byte("GET / HTTP/1.1\r\n\r\n"), framingHello("fragment.example", 8000)} {
		f.Add(p, byte(7))
	}
	f.Fuzz(func(t *testing.T, wire []byte, chunkByte byte) {
		if len(wire) > 128<<10 {
			return
		} // Bound the fuzz workload, not the library.
		raw := lifecycleStream(t)
		w := WrapConn(raw, Options{TLSRec: []Pos{{Offset: 1, FromSNI: true}}, Split: []Pos{{Offset: 3, FromSNI: true}}})
		defer w.Close()
		chunk := 1 + int(chunkByte)%64
		for start := 0; start < len(wire); {
			end := start + chunk
			if end > len(wire) {
				end = len(wire)
			}
			n, err := w.Write(wire[start:end])
			if n < 0 || n > end-start {
				t.Fatal("invalid Write count")
			}
			if err != nil {
				return
			}
			if n != end-start {
				t.Fatal("successful short Write")
			}
			start = end
		}
		var scanner helloScanner
		frame, err := scanner.scan(wire, (*ClientHelloOptions)(nil).limits())
		if err == ErrNotClientHello {
			if !bytes.Equal(raw.data, wire) {
				t.Fatal("malformed/non-TLS input changed")
			}
			return
		}
		if err != nil {
			return
		}
		end, payload := 0, 0
		for payload < frame.size {
			if len(raw.data)-end < 5 {
				t.Fatal("incomplete output header")
			}
			n := int(raw.data[end+3])<<8 | int(raw.data[end+4])
			if n == 0 || n > maxRecordPayload || n > len(raw.data)-end-5 {
				t.Fatal("invalid output record")
			}
			payload += n
			end += 5 + n
		}
		if !bytes.Equal(framingPayload(t, raw.data[:end]), framingPayload(t, wire[:frame.wireLen])) {
			t.Fatal("incremental assembly changed logical bytes")
		}
		if !bytes.Equal(raw.data[end:], wire[frame.wireLen:]) {
			t.Fatal("incremental assembly changed trailing bytes")
		}
	})
}
