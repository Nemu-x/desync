package desync

import (
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"testing"
	"time"
)

// TestMeasureSplitWaitLatency records how long the first Write of a split
// ClientHello takes on loopback with each SplitWait mode. It is a measurement,
// not a pass/fail check: run it with DESYNC_MEASURE=1 and -v.
func TestMeasureSplitWaitLatency(t *testing.T) {
	if os.Getenv("DESYNC_MEASURE") == "" {
		t.Skip("set DESYNC_MEASURE=1 to measure")
	}
	const samples = 1000
	hello := captureHello(t, "example.test")
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// The server closes first, so TIME_WAIT does not use client ports.
			go func() { _, _ = io.ReadFull(c, make([]byte, len(hello))); c.Close() }()
		}
	}()
	caps := PlatformCapabilities().Ack
	for _, mode := range []SplitWait{SplitWaitNone, SplitWaitSent, SplitWaitAcked} {
		if !caps.Supports(mode) {
			t.Logf("%s/%s: unsupported", runtime.GOOS, mode)
			continue
		}
		opts := Options{
			Split:     []Pos{{Offset: 3}, {Offset: 1, FromSNI: true}, {Offset: 40, FromSNI: true}},
			SplitWait: mode,
		}
		durations := make([]time.Duration, 0, samples)
		for i := 0; i < samples; i++ {
			raw, err := net.Dial("tcp4", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			w := WrapConn(raw, opts)
			elapsed := preciseClock()
			_, err = w.Write(hello)
			durations = append(durations, elapsed())
			_, _ = io.Copy(io.Discard, raw)
			w.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		pct := func(p int) time.Duration { return durations[(len(durations)-1)*p/100] }
		t.Logf("%s %s/%s: n=%d p50=%v p95=%v p99=%v max=%v", runtime.Version(), runtime.GOOS, mode, samples, pct(50), pct(95), pct(99), durations[len(durations)-1])
	}
}

// timedAck becomes true at a fixed instant, like an ACK arriving after an RTT.
type timedAck struct {
	clock func() time.Duration
	at    time.Duration
}

func (a timedAck) reached(SplitWait, int64) (bool, error) { return a.clock() >= a.at, nil }
func (a timedAck) state() (AckState, error)               { return unknownAckState(), nil }

// TestMeasureSplitWaitOvershoot records how long after the condition becomes
// true the polling wait notices it, for conditions that become true between
// 0 and 5 ms (a short real-network RTT). Run with DESYNC_MEASURE=1 and -v.
func TestMeasureSplitWaitOvershoot(t *testing.T) {
	if os.Getenv("DESYNC_MEASURE") == "" {
		t.Skip("set DESYNC_MEASURE=1 to measure")
	}
	const samples = 500
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	w := WrapConn(a, Options{Split: []Pos{{Offset: 1}}, SplitWait: SplitWaitAcked}).(*Conn)
	over := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		clock := preciseClock()
		at := time.Duration(i%50) * 100 * time.Microsecond
		if err := w.waitSplit(timedAck{clock: clock, at: at}, 1); err != nil {
			t.Fatal(err)
		}
		over = append(over, clock()-at)
	}
	sort.Slice(over, func(i, j int) bool { return over[i] < over[j] })
	pct := func(p int) time.Duration { return over[(len(over)-1)*p/100] }
	t.Logf("%s %s overshoot: n=%d p50=%v p95=%v p99=%v max=%v", runtime.Version(), runtime.GOOS, samples, pct(50), pct(95), pct(99), over[len(over)-1])
}
