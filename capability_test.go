package desync

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPlatformCapabilitiesPerOS(t *testing.T) {
	c := PlatformCapabilities()
	if c.OS != runtime.GOOS || c.FakeTCP != SupportsFake() || c.FakeUDP != SupportsUDPFake() {
		t.Fatalf("inconsistent capabilities: %+v", c)
	}
	var want AckCapability
	ttl := false
	switch runtime.GOOS {
	case "windows":
		want = AckCapability{Mechanism: "SIO_TCP_INFO", Sent: true, Acked: true}
		ttl = true
	case "linux", "android":
		want = AckCapability{Mechanism: "SIOCOUTQ/SIOCOUTQNSD", Sent: true, Acked: true, Reliable: true}
	case "darwin", "ios":
		want = AckCapability{Mechanism: "SO_NWRITE", Acked: true, Reliable: true}
	}
	if c.Ack != want || c.TTLControl != ttl {
		t.Fatalf("%s capabilities: %+v, want ack %+v ttl %v", runtime.GOOS, c, want, ttl)
	}
	if !c.Ack.Supports(SplitWaitNone) || c.Ack.Supports(SplitWait(9)) {
		t.Fatal("Supports: wrong result for none/unknown")
	}
}

func TestSplitWaitParseAndString(t *testing.T) {
	for _, w := range []SplitWait{SplitWaitNone, SplitWaitSent, SplitWaitAcked} {
		got, err := ParseSplitWait(w.String())
		if err != nil || got != w {
			t.Fatalf("%v: %v %v", w, got, err)
		}
	}
	if _, err := ParseSplitWait("sleep"); err == nil {
		t.Fatal("accepted unknown split wait")
	}
	if SplitWait(7).String() != "SplitWait(7)" {
		t.Fatal(SplitWait(7).String())
	}
}

func TestSplitWaitValidation(t *testing.T) {
	split := []Pos{{Offset: 12}}
	for _, o := range []Options{
		{SplitWait: SplitWaitAcked},                     // nothing to split
		{TLSRec: split, SplitWait: SplitWaitAcked},      // records only
		{Split: split, SplitWait: SplitWait(3)},         // unknown mode
		{Split: split, SplitWaitTimeout: -time.Second},  // negative bound
		{Split: split, SplitWaitTimeout: 2 * time.Hour}, // above maximum
	} {
		if err := o.Validate(); err == nil {
			t.Fatalf("accepted %+v", o)
		}
	}
	caps := PlatformCapabilities().Ack
	for _, mode := range []SplitWait{SplitWaitSent, SplitWaitAcked} {
		for _, o := range []Options{
			{Split: split, SplitWait: mode},
			{Random: &RandomOptions{Split: []RandomCut{{From: Pos{Offset: 1}, To: Pos{Offset: 40}}}}, SplitWait: mode},
		} {
			err := o.Validate()
			if caps.Supports(mode) && err != nil {
				t.Fatalf("%v rejected on %s: %v", mode, runtime.GOOS, err)
			}
			if !caps.Supports(mode) && !errors.Is(err, ErrSplitWaitUnsupported) {
				t.Fatalf("%v on %s: %v, want ErrSplitWaitUnsupported", mode, runtime.GOOS, err)
			}
		}
	}
}

func TestSplitWaitKey(t *testing.T) {
	base := Options{Split: []Pos{{Offset: 12}}}
	if strings.Contains(base.Key(), "wait") {
		t.Fatalf("key changed for options without SplitWait: %s", base.Key())
	}
	acked := base
	acked.SplitWait = SplitWaitAcked
	sent := base
	sent.SplitWait = SplitWaitSent
	bounded := acked
	bounded.SplitWaitTimeout = time.Second
	keys := map[string]bool{base.Key(): true, acked.Key(): true, sent.Key(): true, bounded.Key(): true}
	if len(keys) != 4 {
		t.Fatalf("SplitWait not part of the key: %v", keys)
	}
}

// A requested wait that cannot be observed fails before any byte is sent; it
// is never replaced by back-to-back writes or a sleep.
func TestSplitWaitUnobservableFailsBeforeSending(t *testing.T) {
	mode := SplitWaitAcked
	caps := PlatformCapabilities().Ack
	if !caps.Acked && caps.Sent {
		mode = SplitWaitSent
	}
	a, b := net.Pipe()
	defer b.Close()
	w := WrapConn(a, Options{Split: []Pos{{Offset: 12}}, SplitWait: mode})
	got := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(b)
		got <- data
	}()
	_, err := w.Write(captureHello(t, "example.test"))
	want := ErrSplitWaitRequiresTCP
	if !caps.Supports(mode) {
		want = ErrSplitWaitUnsupported
	}
	if !errors.Is(err, want) {
		t.Fatalf("Write: %v, want %v", err, want)
	}
	if _, err := w.Write([]byte("later")); err == nil {
		t.Fatal("connection usable after failed split wait")
	}
	select {
	case data := <-got:
		if len(data) != 0 {
			t.Fatalf("%d bytes reached the peer", len(data))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("connection was not closed")
	}
}

func TestProbeConnRejectsNonSocket(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := ProbeConn(a); !errors.Is(err, ErrSplitWaitRequiresTCP) {
		t.Fatalf("ProbeConn(pipe): %v", err)
	}
	if _, err := ProbeConn(WrapConn(a, Options{TLSRec: []Pos{{Offset: 1}}})); !errors.Is(err, ErrSplitWaitRequiresTCP) {
		t.Fatalf("ProbeConn(wrapped pipe): %v", err)
	}
}

// stubAck reaches its condition after a number of polls (never when < 0).
type stubAck struct {
	after int32
	polls atomic.Int32
	err   error
}

func (s *stubAck) reached(SplitWait, int64) (bool, error) {
	n := s.polls.Add(1)
	if s.err != nil {
		return false, s.err
	}
	return s.after >= 0 && n > s.after, nil
}

func (s *stubAck) state() (AckState, error) { return unknownAckState(), nil }

func stubWaitConn(t *testing.T, timeout time.Duration) (*Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return WrapConn(a, Options{Split: []Pos{{Offset: 12}}, SplitWait: SplitWaitAcked, SplitWaitTimeout: timeout}).(*Conn), b
}

func TestSplitAckWaitEndsWhenObserved(t *testing.T) {
	w, _ := stubWaitConn(t, 0)
	obs := &stubAck{after: 40}
	if err := w.waitSplit(obs, 10); err != nil {
		t.Fatal(err)
	}
	if obs.polls.Load() != 41 {
		t.Fatalf("polls: %d", obs.polls.Load())
	}
}

func TestSplitAckWaitTimeout(t *testing.T) {
	w, _ := stubWaitConn(t, 30*time.Millisecond)
	start := time.Now()
	err := w.waitSplit(&stubAck{after: -1}, 1)
	if !errors.Is(err, ErrSplitWaitTimeout) {
		t.Fatalf("wait: %v", err)
	}
	if d := time.Since(start); d < 30*time.Millisecond || d > 2*time.Second {
		t.Fatalf("timeout after %v", d)
	}
}

func TestSplitAckWaitObserverError(t *testing.T) {
	w, _ := stubWaitConn(t, 0)
	boom := errors.New("boom")
	if err := w.waitSplit(&stubAck{err: boom}, 1); !errors.Is(err, boom) {
		t.Fatalf("wait: %v", err)
	}
	w.Close()
	if err := w.waitSplit(&stubAck{err: boom}, 1); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("wait after close: %v", err)
	}
}

func TestSplitAckWaitHonorsDeadline(t *testing.T) {
	w, _ := stubWaitConn(t, time.Minute)
	if err := w.SetWriteDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := w.waitSplit(&stubAck{after: -1}, 1); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("wait: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("deadline honored after %v", d)
	}
}

func TestSplitAckWaitInterruptedByCloseOrDeadlineChange(t *testing.T) {
	for _, action := range []string{"close", "deadline", "both-deadlines"} {
		t.Run(action, func(t *testing.T) {
			w, _ := stubWaitConn(t, time.Minute)
			obs := &stubAck{after: -1}
			done := make(chan error, 1)
			go func() { done <- w.waitSplit(obs, 1) }()
			for obs.polls.Load() < splitWaitSpins+4 {
				runtime.Gosched()
			}
			want := error(os.ErrDeadlineExceeded)
			switch action {
			case "close":
				w.Close()
				want = net.ErrClosed
			case "deadline":
				w.SetWriteDeadline(time.Now().Add(-time.Second))
			default:
				w.SetDeadline(time.Now().Add(-time.Second))
			}
			select {
			case err := <-done:
				if !errors.Is(err, want) {
					t.Fatalf("wait: %v, want %v", err, want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("wait ignored", action)
			}
		})
	}
}

func TestSplitAckWaitDeadlineCanBeExtended(t *testing.T) {
	w, _ := stubWaitConn(t, time.Minute)
	if err := w.SetWriteDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	obs := &stubAck{after: 300}
	done := make(chan error, 1)
	go func() { done <- w.waitSplit(obs, 1) }()
	for obs.polls.Load() < splitWaitSpins+2 {
		runtime.Gosched()
	}
	if err := w.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("wait did not finish")
	}
}

func loopbackPair(t testing.TB, network string) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	host := "127.0.0.1"
	if network == "tcp6" {
		host = "[::1]"
	}
	ln, err := net.Listen(network, host+":0")
	if err != nil {
		t.Skipf("%s loopback unavailable: %v", network, err)
	}
	defer ln.Close()
	client, err := net.Dial(network, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := ln.Accept()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client.(*net.TCPConn), server.(*net.TCPConn)
}

func TestProbeConnLoopback(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			client, _ := loopbackPair(t, network)
			got, err := ProbeConn(WrapConn(client, Options{TLSRec: []Pos{{Offset: 1}}}))
			if err != nil {
				t.Fatal(err)
			}
			switch runtime.GOOS {
			case "windows", "linux", "android", "darwin", "ios":
				if got.TTLErr != nil || got.TTL < 1 || got.TTL > 255 {
					t.Fatalf("TTL: %d %v", got.TTL, got.TTLErr)
				}
			}
			platform := PlatformCapabilities().Ack
			if got.Ack != platform || (platform.Acked || platform.Sent) != (got.AckErr == nil) {
				t.Fatalf("ack: %+v %v, platform %+v", got.Ack, got.AckErr, platform)
			}
			if got.AckErr == nil {
				t.Logf("%s %s: TTL %d, state %+v", runtime.GOOS, platform.Mechanism, got.TTL, got.State)
				s := got.State
				if platform.Reliable && s.Unacked != 0 {
					t.Fatalf("idle socket reports unacknowledged bytes: %+v", s)
				}
			}
		})
	}
}

// Every supported mode transmits the exact stream on a real socket and leaves
// the kernel reporting the condition it waited for.
func TestSplitAckNativeLoopback(t *testing.T) {
	caps := PlatformCapabilities().Ack
	for _, mode := range []SplitWait{SplitWaitSent, SplitWaitAcked} {
		if !caps.Supports(mode) {
			continue
		}
		for _, network := range []string{"tcp4", "tcp6"} {
			t.Run(mode.String()+"/"+network, func(t *testing.T) {
				client, server := loopbackPair(t, network)
				hello := captureHello(t, "example.test")
				opts := Options{
					TLSRec:    []Pos{{Offset: 1, FromSNI: true}},
					Split:     []Pos{{Offset: 3}, {Offset: 1, FromSNI: true}, {Offset: 40, FromSNI: true}},
					SplitWait: mode,
				}
				w := WrapConn(client, opts)
				_ = w.SetWriteDeadline(time.Now().Add(10 * time.Second))
				tail := []byte("after the hello")
				input := append(append([]byte(nil), hello...), tail...)
				read := make(chan []byte, 1)
				go func() {
					_ = server.SetReadDeadline(time.Now().Add(10 * time.Second))
					buf := make([]byte, 0, 4096)
					chunk := make([]byte, 4096)
					for !bytes.HasSuffix(buf, tail) {
						n, err := server.Read(chunk)
						buf = append(buf, chunk[:n]...)
						if err != nil {
							break
						}
					}
					read <- buf
				}()
				n, err := w.Write(input)
				if err != nil || n != len(input) {
					t.Fatalf("Write: %d %v", n, err)
				}
				got := <-read
				want := FragmentRecord(hello, resolve(opts.TLSRec, mustParse(t, hello), recordHeaderLen, len(hello)))
				want = append(want, tail...)
				if !bytes.Equal(got, want) {
					t.Fatalf("stream changed: got %d bytes, want %d", len(got), len(want))
				}
			})
		}
	}
}

func mustParse(t *testing.T, rec []byte) Hello {
	t.Helper()
	h, err := ParseHello(rec)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// The observer must report the condition as unmet while the peer's window is
// full and met once the peer has read everything: it reflects the socket, not
// the completion of Write.
func TestSplitAckObserverTracksPeerWindow(t *testing.T) {
	caps := PlatformCapabilities().Ack
	if !caps.Acked && !caps.Sent {
		t.Skipf("no ACK observation on %s", runtime.GOOS)
	}
	client, server := loopbackPair(t, "tcp4")
	if err := server.SetReadBuffer(32 << 10); err != nil {
		t.Fatal(err)
	}
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	obs, err := newAckObserver(raw)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{'a'}, 1<<20)
	written := make(chan error, 1)
	go func() {
		_ = client.SetWriteDeadline(time.Now().Add(20 * time.Second))
		_, err := client.Write(payload)
		written <- err
	}()
	time.Sleep(100 * time.Millisecond)
	for _, mode := range []SplitWait{SplitWaitSent, SplitWaitAcked} {
		if !caps.Supports(mode) {
			continue
		}
		done, err := obs.reached(mode, int64(len(payload)))
		if err != nil || done {
			t.Fatalf("%v reported with a full peer window: %v %v", mode, done, err)
		}
	}
	state, err := obs.state()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("blocked: %+v", state)
	_ = server.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(server, make([]byte, len(payload))); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	for _, mode := range []SplitWait{SplitWaitSent, SplitWaitAcked} {
		if !caps.Supports(mode) {
			continue
		}
		end := time.Now().Add(5 * time.Second)
		for {
			done, err := obs.reached(mode, int64(len(payload)))
			if err != nil {
				t.Fatal(err)
			}
			if done {
				break
			}
			if time.Now().After(end) {
				state, _ := obs.state()
				t.Fatalf("%v not reported after the peer read everything: %+v", mode, state)
			}
			time.Sleep(time.Millisecond)
		}
	}
	state, _ = obs.state()
	t.Logf("drained: %+v", state)
}
