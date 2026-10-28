package desync

import (
	"errors"
	"net"
	"os"
	"runtime"
	"testing"
	"time"
)

func boundedHelloOptions(limits *ClientHelloOptions) Options {
	return Options{TLSRec: []Pos{{Offset: 1, FromSNI: true}}, ClientHello: limits}
}

func TestClientHelloLimitsValidationAndCopy(t *testing.T) {
	for _, limit := range []ClientHelloOptions{{MaxSize: -1}, {MaxSize: 3}, {MaxSize: maxClientHelloSize + 1}, {MaxRecords: -1}, {MaxRecords: maxClientHelloRecords + 1}, {Timeout: -1}, {Timeout: maxClientHelloTimeout + 1}} {
		if err := boundedHelloOptions(&limit).Validate(); err == nil {
			t.Fatalf("invalid limits accepted: %+v", limit)
		}
	}
	limits := &ClientHelloOptions{MaxSize: 512, MaxRecords: 8, Timeout: time.Second}
	raw := lifecycleStream(t)
	w := WrapConn(raw, boundedHelloOptions(limits))
	defer w.Close()
	limits.MaxSize = 4
	limits.MaxRecords = 1
	limits.Timeout = time.Nanosecond
	rec := reframeInput(framingHello("fragment.example", 0), 1, 2, 3)
	if _, err := w.Write(rec); err != nil {
		t.Fatalf("caller mutation affected wrapper: %v", err)
	}
}

func TestClientHelloLimitsFailBeforeTransmission(t *testing.T) {
	rec := framingHello("fragment.example", 0)
	for _, tc := range []struct {
		limits ClientHelloOptions
		input  []byte
		want   error
	}{
		{ClientHelloOptions{MaxSize: len(rec) - 6}, rec[:9], ErrClientHelloTooLarge},
		{ClientHelloOptions{MaxRecords: 1}, reframeInput(rec, 1), ErrTooManyClientHelloRecords},
	} {
		raw := lifecycleStream(t)
		w := WrapConn(raw, boundedHelloOptions(&tc.limits))
		defer w.Close()
		if n, err := w.Write(tc.input[:1]); n != 1 || err != nil {
			t.Fatal(n, err)
		}
		if n, err := w.Write(tc.input[1:]); n != 0 || !errors.Is(err, tc.want) {
			t.Fatalf("limit: %d %v want %v", n, err, tc.want)
		}
		if n, err := w.Write([]byte("must not continue")); n != 0 || !errors.Is(err, tc.want) {
			t.Fatalf("limit not terminal: %d %v", n, err)
		}
		if raw.calls != 0 {
			t.Fatal("limited handshake reached socket")
		}
	}
	// A limit exactly matching the logical handshake is valid; headers do not
	// consume this size budget.
	raw := lifecycleStream(t)
	w := WrapConn(raw, boundedHelloOptions(&ClientHelloOptions{MaxSize: len(rec) - 5, MaxRecords: 2}))
	defer w.Close()
	if _, err := w.Write(reframeInput(rec, 1)); err != nil {
		t.Fatal(err)
	}
}

func TestClientHelloManyRecordsAndBoundedStorage(t *testing.T) {
	rec := framingHello("fragment.example", 600)
	var cuts []int
	for i := 1; i < len(rec)-5; i++ {
		cuts = append(cuts, i)
	}
	wire := reframeInput(rec, cuts...)
	if _, err := ParseHello(wire); !errors.Is(err, ErrTooManyClientHelloRecords) {
		t.Fatalf("default record cap: %v", err)
	}
	raw := lifecycleStream(t)
	w := WrapConn(raw, boundedHelloOptions(&ClientHelloOptions{MaxRecords: 1024})).(*Conn)
	defer w.Close()
	for i := range wire {
		if _, err := w.Write(wire[i : i+1]); err != nil {
			t.Fatalf("byte=%d: %v", i, err)
		}
		if w.pending != nil && cap(w.pending.buf) > w.opts.ClientHello.limits().wireSize() {
			t.Fatal("assembly capacity exceeded wire bound")
		}
	}
	if got := framingPayload(t, raw.data); string(got) != string(rec[5:]) {
		t.Fatal("many-record handshake changed")
	}
}

func TestIncompleteClientHelloTimeoutWakesReadAndWrite(t *testing.T) {
	a, peer := net.Pipe()
	defer peer.Close()
	w := WrapConn(a, boundedHelloOptions(&ClientHelloOptions{Timeout: 25 * time.Millisecond}))
	defer w.Close()
	if n, err := w.Write([]byte{22}); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	read := make(chan error, 1)
	go func() { _, err := w.Read(make([]byte, 1)); read <- err }()
	select {
	case err := <-read:
		var timeout net.Error
		if !errors.Is(err, ErrClientHelloTimeout) || !errors.Is(err, os.ErrDeadlineExceeded) || !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("timeout reason: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("incomplete assembly left Read blocked")
	}
	if n, err := w.Write([]byte{3}); n != 0 || !errors.Is(err, ErrClientHelloTimeout) {
		t.Fatalf("expired assembly accepted input: %d %v", n, err)
	}
}

func TestClientHelloAssemblyTimeoutIsNotExtendedByInput(t *testing.T) {
	raw := lifecycleStream(t)
	w := WrapConn(raw, boundedHelloOptions(&ClientHelloOptions{Timeout: 40 * time.Millisecond}))
	defer w.Close()
	rec := framingHello("fragment.example", 8000)
	if _, err := w.Write(rec[:1]); err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	limit := time.NewTimer(2 * time.Second)
	defer limit.Stop()
	for i := 1; i < len(rec); i++ {
		select {
		case <-ticker.C:
		case <-limit.C:
			t.Fatal("new fragments kept extending assembly timeout")
		}
		_, err := w.Write(rec[i : i+1])
		if errors.Is(err, ErrClientHelloTimeout) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("test completed input before observing absolute assembly timeout")
}

func TestClientHelloTimerStopsOnCompletionOrClose(t *testing.T) {
	for _, complete := range []bool{false, true} {
		raw := lifecycleStream(t)
		w := WrapConn(raw, boundedHelloOptions(&ClientHelloOptions{Timeout: 50 * time.Millisecond}))
		defer w.Close()
		rec := framingHello("fragment.example", 0)
		if _, err := w.Write(rec[:1]); err != nil {
			t.Fatal(err)
		}
		if complete {
			if _, err := w.Write(rec[1:]); err != nil {
				t.Fatal(err)
			}
		} else {
			w.Close()
		}
		<-time.After(100 * time.Millisecond)
		_, err := w.Write([]byte("later bytes"))
		if complete && err != nil {
			t.Fatalf("completion left stale timer: %v", err)
		}
		if !complete && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Close became an assembly timeout: %v", err)
		}
	}
}

func TestClientHelloConcurrentCompletionAndClose(t *testing.T) {
	for i := 0; i < 100; i++ {
		raw := lifecycleStream(t)
		w := WrapConn(raw, boundedHelloOptions(&ClientHelloOptions{Timeout: time.Millisecond}))
		rec := framingHello("fragment.example", 0)
		if _, err := w.Write(rec[:1]); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := w.Write(rec[1:]); done <- err }()
		w.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, ErrClientHelloTimeout) {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Close deadlocked completion")
		}
	}
}

type framingDiscard struct{ net.Conn }

func (*framingDiscard) Write(p []byte) (int, error) { return len(p), nil }

func TestLargeCoalescedTailHasBoundedAssemblyAllocation(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	w := WrapConn(&framingDiscard{a}, boundedHelloOptions(nil))
	defer w.Close()
	rec := framingHello("fragment.example", 0)
	if _, err := w.Write(rec[:1]); err != nil {
		t.Fatal(err)
	}
	p := make([]byte, len(rec)-1+(4<<20))
	copy(p, rec[1:])
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if n, err := w.Write(p); n != len(p) || err != nil {
		t.Fatal(n, err)
	}
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 256<<10 {
		t.Fatalf("coalesced tail was buffered: allocated=%d", allocated)
	}
}
