package desync

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// scriptedStream records writes while using a real pipe for deadline/Close
// methods. Its injected failures satisfy Write's partial-count/error contract.
type scriptedStream struct {
	net.Conn
	mu                  sync.Mutex
	data                []byte
	calls               int
	failCall, failAfter int
	first               chan struct{}
}

func (s *scriptedStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	s.calls++
	n, call := len(p), s.calls
	var err error
	if call == s.failCall {
		n = s.failAfter
		if n > len(p) {
			n = len(p)
		}
		err = io.ErrUnexpectedEOF
	}
	s.data = append(s.data, p[:n]...)
	if call == 1 && s.first != nil {
		close(s.first)
	}
	s.mu.Unlock()
	return n, err
}

func lifecycleStream(t *testing.T) *scriptedStream {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return &scriptedStream{Conn: a}
}

func TestBufferedWriteChecksCloseAndResettableDeadline(t *testing.T) {
	rec := defaultFakeTLS()
	for _, closeFirst := range []bool{false, true} {
		raw := lifecycleStream(t)
		w := WrapConn(raw, Options{TLSRec: []Pos{{Offset: 12}}})
		if closeFirst {
			w.Close()
		} else {
			w.SetWriteDeadline(time.Now().Add(-time.Second))
		}
		n, err := w.Write(rec[:1])
		want := error(os.ErrDeadlineExceeded)
		if closeFirst {
			want = net.ErrClosed
		}
		if n != 0 || !errors.Is(err, want) {
			t.Fatalf("closed=%t: Write=%d,%v", closeFirst, n, err)
		}
		if raw.calls != 0 {
			t.Fatal("rejected Write reached socket")
		}
		if closeFirst {
			continue
		}
		if err = w.SetWriteDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		if n, err = w.Write(rec[:17]); n != 17 || err != nil {
			t.Fatalf("initial fragment: %d %v", n, err)
		}
		w.SetWriteDeadline(time.Now().Add(-time.Second))
		if n, err = w.Write(rec[17:18]); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("pending fragment: %d %v", n, err)
		}
		w.SetWriteDeadline(time.Time{})
		if n, err = w.Write(rec[17:]); n != len(rec)-17 || err != nil {
			t.Fatalf("completed fragment: %d %v", n, err)
		}
		var payload []byte
		for _, r := range records(t, raw.data) {
			payload = append(payload, r[5:]...)
		}
		if !bytes.Equal(payload, rec[5:]) {
			t.Fatal("deadline retry changed pending bytes")
		}
	}
}

func TestFirstRecordPartialWriteLogicalCount(t *testing.T) {
	rec := defaultFakeTLS()
	// TLSRec adds a five-byte header at original offset 12. Those generated
	// bytes must not be reported as extra bytes consumed from the caller.
	for _, tc := range []struct{ wire, logical int }{{0, 0}, {3, 3}, {5, 5}, {12, 12}, {15, 12}, {17, 12}, {20, 15}, {len(rec) + 5, len(rec)}} {
		for _, buffered := range []int{0, 8} {
			raw := lifecycleStream(t)
			raw.failCall, raw.failAfter = 1, tc.wire
			w := WrapConn(raw, Options{TLSRec: []Pos{{Offset: 12}}})
			if buffered > 0 {
				if _, err := w.Write(rec[:buffered]); err != nil {
					t.Fatal(err)
				}
			}
			n, err := w.Write(rec[buffered:])
			want := tc.logical - buffered
			if want < 0 {
				want = 0
			}
			if n != want || !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("wire=%d buffered=%d: n=%d want=%d error=%v", tc.wire, buffered, n, want, err)
			}
			if n, err = w.Write([]byte("must not replay")); n != 0 || !errors.Is(err, io.ErrUnexpectedEOF) || raw.calls != 1 {
				t.Fatalf("terminal failure: %d %v calls=%d", n, err, raw.calls)
			}
		}
	}
}

func TestPartialWriteAcrossMultipleGeneratedHeaders(t *testing.T) {
	for _, tc := range []struct{ wire, logical int }{{24, 19}, {25, 20}, {27, 20}, {30, 20}, {35, 25}} {
		raw := lifecycleStream(t)
		raw.failCall, raw.failAfter = 1, tc.wire
		w := WrapConn(raw, Options{TLSRec: []Pos{{Offset: 12}, {Offset: 20}}})
		n, err := w.Write(defaultFakeTLS())
		if n != tc.logical || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("wire=%d: n=%d want=%d err=%v", tc.wire, n, tc.logical, err)
		}
	}
}

func TestTrailingPartialWriteCountAndTerminalError(t *testing.T) {
	rec, tail := defaultFakeTLS(), []byte("trailing-data")
	for _, buffered := range []int{0, 17} {
		raw := lifecycleStream(t)
		raw.failCall, raw.failAfter = 2, 3
		w := WrapConn(raw, Options{TLSRec: []Pos{{Offset: 12}}})
		if buffered > 0 {
			w.Write(rec[:buffered])
		}
		p := append(append([]byte(nil), rec[buffered:]...), tail...)
		n, err := w.Write(p)
		if n != len(rec)-buffered+3 || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("buffered=%d: %d %v", buffered, n, err)
		}
		if n, err = w.Write(tail[3:]); n != 0 || !errors.Is(err, io.ErrUnexpectedEOF) || raw.calls != 2 {
			t.Fatalf("tail replay: %d %v calls=%d", n, err, raw.calls)
		}
	}
}

func TestPartialSplitAccumulatesCounts(t *testing.T) {
	raw := lifecycleStream(t)
	raw.failCall, raw.failAfter = 2, 4
	w := WrapConn(raw, Options{TLSRec: []Pos{{Offset: 12}}, Split: []Pos{{Offset: 20}}})
	n, err := w.Write(defaultFakeTLS())
	if n != 24 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("split count: %d %v", n, err)
	}
}

func TestSplitWaitInterruptedByCloseOrDeadlineChange(t *testing.T) {
	for _, both := range []bool{false, true} {
		for _, closeConn := range []bool{false, true} {
			raw := lifecycleStream(t)
			raw.first = make(chan struct{})
			w := WrapConn(raw, Options{Split: []Pos{{Offset: 12}}, SplitDelay: 30 * time.Second})
			t.Cleanup(func() { w.Close() })
			done := make(chan error, 1)
			go func() { _, err := w.Write(defaultFakeTLS()); done <- err }()
			select {
			case <-raw.first:
			case <-time.After(2 * time.Second):
				t.Fatal("first write did not start")
			}
			want := error(os.ErrDeadlineExceeded)
			if closeConn {
				w.Close()
				want = net.ErrClosed
			} else if both {
				w.SetDeadline(time.Now().Add(-time.Second))
			} else {
				w.SetWriteDeadline(time.Now().Add(-time.Second))
			}
			select {
			case err := <-done:
				if !errors.Is(err, want) {
					t.Fatalf("split wait: %v want %v", err, want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("split wait ignored Close/deadline change")
			}
		}
	}
}

func TestSplitWaitCanClearDeadline(t *testing.T) {
	raw := lifecycleStream(t)
	raw.first = make(chan struct{})
	w := WrapConn(raw, Options{Split: []Pos{{Offset: 12}}, SplitDelay: 50 * time.Millisecond})
	defer w.Close()
	if err := w.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := w.Write(defaultFakeTLS()); done <- err }()
	<-raw.first
	if err := w.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cleared deadline left wait blocked")
	}
	if raw.calls != 2 {
		t.Fatalf("writes=%d", raw.calls)
	}
}

func TestCloseAfterIncompleteWrite(t *testing.T) {
	raw := lifecycleStream(t)
	w := WrapConn(raw, Options{TLSRec: []Pos{{Offset: 12}}})
	if n, err := w.Write(defaultFakeTLS()[:17]); n != 17 || err != nil {
		t.Fatalf("buffer: %d %v", n, err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := w.Write(defaultFakeTLS()[17:]); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed buffer: %d %v", n, err)
	}
	if raw.calls != 0 {
		t.Fatal("incomplete bytes sent after Close")
	}
}

func TestSplitWaitDoesNotBlockReadAndCloseWakesQueuedWriter(t *testing.T) {
	a, peer := net.Pipe()
	defer peer.Close()
	raw := &scriptedStream{Conn: a, first: make(chan struct{})}
	w := WrapConn(raw, Options{Split: []Pos{{Offset: 12}}, SplitDelay: 30 * time.Second})
	defer w.Close()
	writes := make(chan error, 2)
	go func() { _, err := w.Write(defaultFakeTLS()); writes <- err }()
	select {
	case <-raw.first:
	case <-time.After(2 * time.Second):
		t.Fatal("first write did not start")
	}
	go func() { _, err := w.Write([]byte("queued application bytes")); writes <- err }()
	reads := make(chan error, 1)
	go func() { _, err := io.ReadFull(w, make([]byte, 2)); reads <- err }()
	go func() { peer.Write([]byte("ok")) }()
	select {
	case err := <-reads:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first Write blocked independent Read")
	}
	w.Close()
	for i := 0; i < 2; i++ {
		select {
		case err := <-writes:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Close did not wake writers")
		}
	}
	if raw.calls != 1 {
		t.Fatalf("queued bytes escaped failed first write: %d", raw.calls)
	}
}

func TestSplitWaitObservesDeadlineWithoutUpdate(t *testing.T) {
	raw := lifecycleStream(t)
	w := WrapConn(raw, Options{Split: []Pos{{Offset: 12}}, SplitDelay: 30 * time.Second})
	defer w.Close()
	w.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	done := make(chan error, 1)
	go func() { _, err := w.Write(defaultFakeTLS()); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("split wait exceeded write deadline")
	}
}

func TestSplitDelayValidation(t *testing.T) {
	if err := (Options{Split: []Pos{{Offset: 12}}, SplitDelay: -time.Second}).Validate(); err == nil {
		t.Fatal("negative split delay accepted")
	}
}
