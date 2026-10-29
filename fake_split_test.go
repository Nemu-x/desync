package desync

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

type fakeCall struct {
	real, payload []byte
	queued        bool
}

// observeFake replaces the native backend with one that records the fake
// piece, writes its original bytes (what the server reads after the
// retransmission) and runs the rest. fail makes the backend fail before it
// writes.
func observeFake(t *testing.T, fail error) *[]fakeCall {
	t.Helper()
	var calls []fakeCall
	sendFakePieceFunc = func(c *Conn, real, payload []byte, queued bool, rest func() error) error {
		calls = append(calls, fakeCall{append([]byte(nil), real...), append([]byte(nil), payload...), queued})
		if fail != nil {
			return fail
		}
		if err := writeAll(c.Conn, real); err != nil {
			return err
		}
		return rest()
	}
	t.Cleanup(func() { sendFakePieceFunc = (*Conn).sendFakePiece })
	return &calls
}

// wrapFake wraps c and, where the platform has no fake, clears the
// validation error so the sequencing can be checked with the observer.
func wrapFake(c net.Conn, opts Options) *Conn {
	w := WrapConn(c, opts).(*Conn)
	if errors.Is(w.err, ErrFakeUnsupported) {
		w.err = nil
	}
	return w
}

func TestFakeSplitSequence(t *testing.T) {
	hello := framingHello("split.example", 900)
	n := len(hello)
	sni := mustParse(t, hello).SNIOffset
	for _, tc := range []struct {
		name      string
		opts      Options
		segs      []int // segment ends
		fakeStart int
		fakeEnd   int
	}{
		{"fake alone", Options{Fake: &FakeOptions{TTL: 4}}, []int{n - 1, n}, 0, n - 1},
		{"split then fake", Options{Split: []Pos{{Offset: 20}}, Fake: &FakeOptions{TTL: 4}}, []int{20, n - 1, n}, 20, n - 1},
		{"fake then split", Options{Split: []Pos{{Offset: 1, FromSNI: true}}, Fake: &FakeOptions{TTL: 4, Prefix: 10}}, []int{10, sni + 1, n}, 0, 10},
		{"split at the fake end", Options{Split: []Pos{{Offset: 30}, {Offset: 60}}, Fake: &FakeOptions{TTL: 4, Prefix: 60}}, []int{30, 60, n}, 30, 60},
		{"splits around", Options{Split: []Pos{{Offset: 30}, {Offset: 600}}, Fake: &FakeOptions{TTL: 4, Prefix: 300}, SplitDelay: time.Millisecond}, []int{30, 300, 600, n}, 30, 300},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := observeFake(t, nil)
			sink := newSegmentSink(t)
			w := wrapFake(sink, tc.opts)
			tail := []byte("tail")
			input := append(append([]byte(nil), hello...), tail...)
			if got, err := w.Write(input); err != nil || got != len(input) {
				t.Fatalf("Write: %d %v", got, err)
			}
			if !bytes.Equal(sink.data(), input) {
				t.Fatal("server stream changed")
			}
			start := 0
			for i, end := range tc.segs {
				if !bytes.Equal(sink.segs[i], hello[start:end]) {
					t.Fatalf("segment %d is not [%d,%d): %d bytes", i, start, end, len(sink.segs[i]))
				}
				start = end
			}
			if len(*calls) != 1 {
				t.Fatalf("%d fake pieces", len(*calls))
			}
			call := (*calls)[0]
			if !bytes.Equal(call.real, hello[tc.fakeStart:tc.fakeEnd]) || call.queued != (tc.fakeStart > 0) {
				t.Fatalf("fake piece [%d,%d) queued=%v: got %d bytes queued=%v", tc.fakeStart, tc.fakeEnd, tc.fakeStart > 0, len(call.real), call.queued)
			}
			if !bytes.Equal(call.payload, fakePayload(nil, len(call.real))) {
				t.Fatal("the fake piece does not carry the template")
			}
		})
	}
}

// The decoy carries the configured SNI and starts at Offset; the stream
// is unchanged.
func TestFakeSplitDecoy(t *testing.T) {
	hello := framingHello("real.example", 1200)
	calls := observeFake(t, nil)
	sink := newSegmentSink(t)
	w := wrapFake(sink, Options{Split: []Pos{{Offset: 1, FromSNI: true}}, Fake: &FakeOptions{TTL: 4, SNI: []string{"decoy.example"}}})
	if _, err := w.Write(hello); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sink.data(), hello) {
		t.Fatal("server stream changed")
	}
	if h := mustParse(t, (*calls)[0].payload); h.SNI != "decoy.example" {
		t.Fatalf("decoy SNI %q", h.SNI)
	}
	calls = observeFake(t, nil)
	sink = newSegmentSink(t)
	w = wrapFake(sink, Options{Split: []Pos{{Offset: 40}}, Fake: &FakeOptions{TTL: 4, Payload: hello, Offset: 40}})
	if _, err := w.Write(hello); err != nil {
		t.Fatal(err)
	}
	if c := (*calls)[0]; !bytes.Equal(c.payload, c.real) {
		t.Fatal("Offset did not align the decoy with the piece")
	}
}

func TestFakeSplitErrors(t *testing.T) {
	hello := framingHello("err.example", 600)
	t.Run("partial count", func(t *testing.T) {
		observeFake(t, errInjected)
		sink := newSegmentSink(t)
		w := wrapFake(sink, Options{Split: []Pos{{Offset: 25}}, Fake: &FakeOptions{TTL: 4}})
		n, err := w.Write(hello)
		if !errors.Is(err, errInjected) || n != 25 {
			t.Fatalf("Write: %d %v, want the 25 bytes before the fake piece", n, err)
		}
		if _, err := w.Write([]byte("later")); !errors.Is(err, errInjected) {
			t.Fatalf("not terminal: %v", err)
		}
	})
	t.Run("partial count with records", func(t *testing.T) {
		observeFake(t, errInjected)
		sink := newSegmentSink(t)
		w := wrapFake(sink, Options{TLSRec: []Pos{{Offset: 10}}, Split: []Pos{{Offset: 25}}, Fake: &FakeOptions{TTL: 4}})
		if n, err := w.Write(hello); !errors.Is(err, errInjected) || n != 25 {
			t.Fatalf("Write: %d %v", n, err)
		}
	})
	t.Run("first piece", func(t *testing.T) {
		for _, opts := range []Options{
			{Split: []Pos{{Offset: 50}}, Disorder: true, Fake: &FakeOptions{TTL: 4, Prefix: 50}},
			{Split: []Pos{{Offset: 50}}, OOB: &OOBOptions{}, Fake: &FakeOptions{TTL: 4, Prefix: 20}},
		} {
			calls := observeFake(t, nil)
			client, server := loopbackPair(t, "tcp4")
			w := wrapFake(client, opts)
			if errors.Is(w.err, ErrDisorderUnsupported) || errors.Is(w.err, ErrOOBUnsupported) {
				t.Skip(w.err)
			}
			if _, err := w.Write(hello); !errors.Is(err, ErrFakeFirstPiece) {
				t.Fatalf("Write: %v", err)
			}
			_ = server.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if n, _ := server.Read(make([]byte, 16)); n != 0 || len(*calls) != 0 {
				t.Fatalf("%d bytes and %d fake pieces sent", n, len(*calls))
			}
		}
	})
}

// With Disorder or OOB the first piece keeps its method and the fake piece
// follows it.
func TestFakeSplitWithSocketMethods(t *testing.T) {
	hello := captureHello(t, "methods.example")
	for _, m := range []struct {
		disorder bool
		oob      *OOBOptions
	}{{true, nil}, {false, &OOBOptions{}}, {true, &OOBOptions{}}} {
		opts := Options{Split: []Pos{{Offset: 1, FromSNI: true}}, Disorder: m.disorder, OOB: m.oob, Fake: &FakeOptions{TTL: 4, Prefix: -1}}
		t.Run(fmt.Sprintf("disorder=%v,oob=%v", m.disorder, m.oob != nil), func(t *testing.T) {
			calls := observeFake(t, nil)
			client, server := loopbackPair(t, "tcp4")
			before := tcpHop(t, client)
			w := wrapFake(client, opts)
			if w.err != nil {
				t.Skip(w.err)
			}
			_ = w.SetWriteDeadline(time.Now().Add(5 * time.Second))
			tail := []byte("after")
			read := readUntil(server, tail)
			if _, err := w.Write(append(append([]byte(nil), hello...), tail...)); err != nil {
				t.Fatal(err)
			}
			if got := <-read; !bytes.Equal(got, append(append([]byte(nil), hello...), tail...)) {
				t.Fatalf("server stream changed: %d bytes", len(got))
			}
			sni := mustParse(t, hello).SNIOffset
			if len(*calls) != 1 || !bytes.Equal((*calls)[0].real, hello[sni+1:len(hello)-1]) || !(*calls)[0].queued {
				t.Fatalf("fake piece: %+v", *calls)
			}
			if after := tcpHop(t, client); after != before {
				t.Fatalf("hop limit %d -> %d", before, after)
			}
		})
	}
}
