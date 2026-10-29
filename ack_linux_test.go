//go:build linux

package desync

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeRaw is a RawConn whose Control runs f with a placeholder descriptor;
// the injected sockQuery never touches it.
type fakeRaw struct{}

func (fakeRaw) Control(f func(fd uintptr)) error { f(^uintptr(0)); return nil }
func (fakeRaw) Read(func(uintptr) bool) error    { return errors.New("unused") }
func (fakeRaw) Write(func(uintptr) bool) error   { return errors.New("unused") }

// stubQuery is a scripted kernel: SIOCOUTQ, SIOCOUTQNSD and TCP_INFO each
// return a value or an error, and TCP_INFO answers with infoLen bytes.
type stubQuery struct {
	unacked, unsent int64
	outqErr, nsdErr error
	infoLen         int
	infoErr         error
	nsdCalls, infos int
	lastInfoRequest int
}

func (s *stubQuery) query() sockQuery {
	return sockQuery{
		ioctl: func(_ uintptr, req uintptr) (int64, error) {
			switch req {
			case syscall.TIOCOUTQ:
				return s.unacked, s.outqErr
			case siocOUTQNSD:
				s.nsdCalls++
				return s.unsent, s.nsdErr
			}
			return 0, syscall.ENOTTY
		},
		getsockopt: func(_ uintptr, level, option int, buf []byte) (int, error) {
			s.infos++
			s.lastInfoRequest = len(buf)
			if level != syscall.IPPROTO_TCP || option != syscall.TCP_INFO {
				return 0, syscall.ENOPROTOOPT
			}
			if s.infoErr != nil {
				return 0, s.infoErr
			}
			n := s.infoLen
			if n > len(buf) {
				n = len(buf)
			}
			full := make([]byte, 512)
			nativeEndian.PutUint32(full[tcpInfoNotsentOffset:], uint32(s.unsent))
			return copy(buf, full[:n]), nil
		},
	}
}

func useSockQuery(t *testing.T, q sockQuery) {
	t.Helper()
	old := linuxSockQuery
	linuxSockQuery = q
	t.Cleanup(func() { linuxSockQuery = old })
}

func TestLinuxAckFallbackChain(t *testing.T) {
	for _, tc := range []struct {
		name      string
		stub      stubQuery
		mechanism string
		sent      bool
		whyIs     []error // the reason Sent is missing wraps these
	}{
		{"SIOCOUTQNSD", stubQuery{}, ackMechanismOUTQNSD, true, nil},
		{"EACCES, TCP_INFO", stubQuery{nsdErr: syscall.EACCES, infoLen: 232}, ackMechanismTCPInfo, true, nil},
		{"EPERM, TCP_INFO", stubQuery{nsdErr: syscall.EPERM, infoLen: 148}, ackMechanismTCPInfo, true, nil},
		{"EACCES, 4.4 kernel", stubQuery{nsdErr: syscall.EACCES, infoLen: 144}, ackMechanismAcked, false, []error{syscall.EACCES, errNoNotsentBytes}},
		{"EACCES, TCP_INFO fails", stubQuery{nsdErr: syscall.EACCES, infoErr: syscall.ENOPROTOOPT}, ackMechanismAcked, false, []error{syscall.EACCES, syscall.ENOPROTOOPT}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := tc.stub
			stub.unacked, stub.unsent = 30, 7
			useSockQuery(t, stub.query())
			obs, err := newAckObserver(fakeRaw{})
			if err != nil {
				t.Fatal(err)
			}
			ack, why := obs.capability()
			if ack.Mechanism != tc.mechanism || ack.Sent != tc.sent || !ack.Acked || !ack.Reliable {
				t.Fatalf("capability %+v", ack)
			}
			if (why == nil) != tc.sent {
				t.Fatalf("reason %v with Sent %v", why, ack.Sent)
			}
			for _, target := range tc.whyIs {
				if !errors.Is(why, target) {
					t.Fatalf("reason %v does not wrap %v", why, target)
				}
			}
			s, err := obs.state()
			if err != nil {
				t.Fatal(err)
			}
			want := AckState{Unacked: 30, Unsent: 7, InFlight: 23, Sent: -1}
			if !tc.sent {
				want.Unsent, want.InFlight = -1, -1
			}
			if s != want {
				t.Fatalf("state %+v, want %+v", s, want)
			}
			if done, err := obs.reached(SplitWaitAcked, 0); done || err != nil {
				t.Fatalf("acked with 30 unacknowledged bytes: %v %v", done, err)
			}
			done, err := obs.reached(SplitWaitSent, 0)
			if tc.sent && (done || err != nil) {
				t.Fatalf("sent with 7 unsent bytes: %v %v", done, err)
			}
			if !tc.sent && (!errors.Is(err, ErrSplitWaitUnsupported) || !errors.Is(err, tc.whyIs[0])) {
				t.Fatalf("sent wait without a source: %v %v", done, err)
			}
			stub.unacked, stub.unsent = 0, 0
			if done, err := obs.reached(SplitWaitAcked, 0); !done || err != nil {
				t.Fatalf("acked on an empty queue: %v %v", done, err)
			}
			if done, err := obs.reached(SplitWaitSent, 0); tc.sent && (!done || err != nil) {
				t.Fatalf("sent on an empty queue: %v %v", done, err)
			}
			// a denied query is tried once, when the observer is created
			if tc.stub.nsdErr != nil && stub.nsdCalls != 1 {
				t.Fatalf("SIOCOUTQNSD tried %d times", stub.nsdCalls)
			}
			if tc.stub.nsdErr == nil && stub.infos != 0 {
				t.Fatalf("TCP_INFO read %d times although SIOCOUTQNSD works", stub.infos)
			}
			if stub.infos > 0 && stub.lastInfoRequest != tcpInfoNotsentEnd {
				t.Fatalf("TCP_INFO requested with %d bytes", stub.lastInfoRequest)
			}
		})
	}
}

// Errors other than a denial are not a reason to switch sources.
func TestLinuxAckObserverErrors(t *testing.T) {
	for name, stub := range map[string]stubQuery{
		"SIOCOUTQ denied":    {outqErr: syscall.EACCES, infoLen: 232},
		"SIOCOUTQNSD EINVAL": {nsdErr: syscall.EINVAL, infoLen: 232},
		"SIOCOUTQNSD ENOTTY": {nsdErr: syscall.ENOTTY, infoLen: 232},
	} {
		stub := stub
		t.Run(name, func(t *testing.T) {
			useSockQuery(t, stub.query())
			if obs, err := newAckObserver(fakeRaw{}); err == nil {
				t.Fatalf("observer created: %+v", obs)
			}
		})
	}
}

// denyOUTQNSD reproduces an Android app on a real Linux socket: SIOCOUTQNSD
// fails with errno, and TCP_INFO is cut to infoLimit bytes when >= 0 (an
// older kernel).
func denyOUTQNSD(t *testing.T, errno syscall.Errno, infoLimit int) {
	t.Helper()
	useSockQuery(t, sockQuery{
		ioctl: func(fd, req uintptr) (int64, error) {
			if req == siocOUTQNSD {
				return 0, errno
			}
			return socketQueue(fd, req)
		},
		getsockopt: func(fd uintptr, level, option int, buf []byte) (int, error) {
			n, err := getsockoptBytes(fd, level, option, buf)
			if err == nil && level == syscall.IPPROTO_TCP && option == syscall.TCP_INFO && infoLimit >= 0 && n > infoLimit {
				n = infoLimit
			}
			return n, err
		},
	})
}

// The kernel's tcpi_notsent_bytes follows the same queue as SIOCOUTQNSD:
// both are nonzero while the peer's window is full and zero once it read
// everything.
func TestLinuxTCPInfoNotsentMatchesOUTQNSD(t *testing.T) {
	client, server := loopbackPair(t, "tcp4")
	if err := server.SetReadBuffer(32 << 10); err != nil {
		t.Fatal(err)
	}
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	sample := func() (nsd, info int64, ok bool) {
		var e1, e2 error
		if err := raw.Control(func(fd uintptr) {
			nsd, e1 = socketQueue(fd, siocOUTQNSD)
			o := &linuxAck{q: linuxSockQuery}
			info, ok, e2 = o.notsent(fd)
		}); err != nil {
			t.Fatal(err)
		}
		if errors.Is(e1, syscall.EACCES) || errors.Is(e1, syscall.EPERM) {
			t.Skipf("SIOCOUTQNSD denied here (as for Android apps): %v; tcpi_notsent_bytes ok=%v %v", e1, ok, e2)
		}
		if e1 != nil || e2 != nil {
			t.Fatal(e1, e2)
		}
		return nsd, info, ok
	}
	if _, _, ok := sample(); !ok {
		t.Skip("kernel before 4.6: no tcpi_notsent_bytes")
	}
	payload := bytes.Repeat([]byte{'a'}, 1<<20)
	written := make(chan error, 1)
	go func() {
		_ = client.SetWriteDeadline(time.Now().Add(20 * time.Second))
		_, err := client.Write(payload)
		written <- err
	}()
	time.Sleep(100 * time.Millisecond)
	nsd, info, _ := sample()
	if nsd <= 0 || info <= 0 {
		t.Fatalf("full window: SIOCOUTQNSD %d, tcpi_notsent_bytes %d", nsd, info)
	}
	t.Logf("full window: SIOCOUTQNSD %d, tcpi_notsent_bytes %d", nsd, info)
	if _, err := io.ReadFull(server, make([]byte, len(payload))); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if nsd, info, _ := sample(); nsd != 0 || info != 0 {
		t.Fatalf("drained: SIOCOUTQNSD %d, tcpi_notsent_bytes %d", nsd, info)
	}
}

// With SIOCOUTQNSD denied the observer reads TCP_INFO and follows the real
// queue, as TestSplitAckObserverTracksPeerWindow checks for SIOCOUTQNSD.
func TestLinuxAckDeniedTracksPeerWindow(t *testing.T) {
	denyOUTQNSD(t, syscall.EACCES, -1)
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
	if ack, why := obs.capability(); ack.Mechanism != ackMechanismTCPInfo || !ack.Sent {
		t.Skipf("no tcpi_notsent_bytes on this kernel: %+v %v", ack, why)
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
		if done, err := obs.reached(mode, 0); err != nil || done {
			t.Fatalf("%v reported with a full peer window: %v %v", mode, done, err)
		}
	}
	if _, err := io.ReadFull(server, make([]byte, len(payload))); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for _, mode := range []SplitWait{SplitWaitSent, SplitWaitAcked} {
		for {
			done, err := obs.reached(mode, 0)
			if err != nil {
				t.Fatal(err)
			}
			if done {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%v never reported after the peer read everything", mode)
			}
			time.Sleep(time.Millisecond)
		}
	}
}

// PlatformCapabilities on Android lowers the methods that need unsent bytes;
// ProbeCapabilities on a socket restores or confirms them. Both directions
// are checked here on Linux with the Android denial injected.
func TestLinuxCapabilitiesUnderDenial(t *testing.T) {
	// what Android reports (the platform report itself there)
	reason := sentPerSocketReason
	static := PlatformCapabilities()
	if !sentPerSocket {
		reason = "decided per socket"
		static.lowerSentMethods(reason, true)
	}
	if static.Ack != (AckCapability{Mechanism: "SIOCOUTQ", Acked: true, Reliable: true}) ||
		static.FakeTCP || static.Disorder.Supported || !static.OOB || !static.FakeUDP {
		t.Fatalf("android report: %+v", static)
	}
	for _, key := range []string{"split-wait-sent", "fake-tcp", "disorder"} {
		if static.Conditional[key] != reason || static.Unsupported[key] != reason {
			t.Fatalf("%s: conditional %q unsupported %q", key, static.Conditional[key], static.Unsupported[key])
		}
	}

	t.Run("TCP_INFO", func(t *testing.T) {
		denyOUTQNSD(t, syscall.EACCES, -1)
		client, _ := loopbackPair(t, "tcp4")
		conn, err := ProbeConn(client)
		if err != nil {
			t.Fatal(err)
		}
		if conn.Ack.Mechanism != ackMechanismTCPInfo {
			t.Skipf("no tcpi_notsent_bytes on this kernel: %+v", conn)
		}
		got := static.withConn(conn)
		if got.Ack != (AckCapability{Mechanism: ackMechanismTCPInfo, Sent: true, Acked: true, Reliable: true}) ||
			!got.FakeTCP || got.Disorder != (DisorderCapability{Supported: true, Mechanism: "TCP_INFO", Observed: true, Reliable: true}) ||
			len(got.Conditional) != 0 || conn.SentErr != nil {
			t.Fatalf("probed: %+v (sent error %v)", got, conn.SentErr)
		}
		for _, key := range []string{"split-wait-sent", "fake-tcp", "disorder"} {
			if r, ok := got.Unsupported[key]; ok {
				t.Fatalf("%s still unsupported: %q", key, r)
			}
		}
		probed, err := ProbeCapabilities(client)
		if err != nil || probed.Ack != got.Ack || probed.FakeTCP != got.FakeTCP || probed.Disorder != got.Disorder {
			t.Fatalf("ProbeCapabilities: %+v %v", probed, err)
		}
	})

	t.Run("old kernel", func(t *testing.T) {
		denyOUTQNSD(t, syscall.EACCES, 144)
		client, _ := loopbackPair(t, "tcp4")
		got, err := ProbeCapabilities(client)
		if err != nil {
			t.Fatal(err)
		}
		if got.Ack != (AckCapability{Mechanism: ackMechanismAcked, Acked: true, Reliable: true}) ||
			got.FakeTCP || got.Disorder.Supported || !got.OOB || len(got.Conditional) != 0 {
			t.Fatalf("probed: %+v", got)
		}
		for _, key := range []string{"split-wait-sent", "fake-tcp", "disorder"} {
			if r := got.Unsupported[key]; !strings.Contains(r, "SIOCOUTQNSD") || !strings.Contains(r, "tcpi_notsent_bytes") {
				t.Fatalf("%s: reason %q", key, r)
			}
		}
		if _, ok := got.Unsupported["split-wait-acked"]; ok {
			t.Fatal("acked wait reported unsupported")
		}
		conn, err := ProbeConn(client)
		if err != nil || !errors.Is(conn.SentErr, syscall.EACCES) || conn.State.Unsent != -1 || conn.State.Unacked != 0 {
			t.Fatalf("ProbeConn: %+v %v", conn, err)
		}
	})

	// Without injection: SIOCOUTQNSD on Linux; on Android, where the app and
	// shell domains are denied it, TCP_INFO (or nothing on an old kernel).
	t.Run("real socket", func(t *testing.T) {
		client, _ := loopbackPair(t, "tcp4")
		got, err := ProbeCapabilities(client)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := ProbeConn(client)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: ack %+v, disorder %+v, fake %v, sent error %v", runtime.GOOS, got.Ack, got.Disorder, got.FakeTCP, conn.SentErr)
		if len(got.Conditional) != 0 || got.Ack != conn.Ack || !got.Ack.Acked {
			t.Fatalf("probed %+v, conn %+v", got, conn)
		}
		if !sentPerSocket {
			plat := PlatformCapabilities()
			if got.Ack != plat.Ack || got.FakeTCP != plat.FakeTCP || got.Disorder != plat.Disorder {
				t.Fatalf("probed %+v, platform %+v", got, plat)
			}
			return
		}
		if got.Ack.Sent != got.FakeTCP || got.Ack.Sent != got.Disorder.Supported || got.Ack.Sent == (conn.SentErr != nil) {
			t.Fatalf("android probe inconsistent: %+v (sent error %v)", got, conn.SentErr)
		}
	})
}

// With the denial and a kernel that has tcpi_notsent_bytes, every method that
// needs unsent bytes still runs and delivers the exact stream.
func TestLinuxMethodsUnderDenialWithTCPInfo(t *testing.T) {
	requireNotsentBytes(t)
	denyOUTQNSD(t, syscall.EACCES, -1)
	const cut = 40
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run("fake/"+network, func(t *testing.T) {
			linuxFakeRoundTrip(t, network, Options{Fake: &FakeOptions{TTL: 64, Prefix: cut}}, false)
		})
		t.Run("wait-fake/"+network, func(t *testing.T) {
			linuxFakeRoundTrip(t, network, Options{Split: []Pos{{Offset: cut}, {Offset: 3 * cut}}, SplitWait: SplitWaitSent,
				Fake: &FakeOptions{TTL: 64, Prefix: 2 * cut, Offset: cut}}, false)
		})
		t.Run("disorder/"+network, func(t *testing.T) {
			socketMethodRoundTrip(t, network, Options{Split: []Pos{{Offset: 3}, {Offset: 1, FromSNI: true}}, Disorder: true}, false)
		})
		t.Run("disorder-wait-sent/"+network, func(t *testing.T) {
			socketMethodRoundTrip(t, network, Options{Split: []Pos{{Offset: 3}, {Offset: 1, FromSNI: true}}, Disorder: true, SplitWait: SplitWaitSent}, false)
		})
		t.Run("wait-sent/"+network, func(t *testing.T) {
			socketMethodRoundTrip(t, network, Options{Split: []Pos{{Offset: 3}, {Offset: 1, FromSNI: true}}, SplitWait: SplitWaitSent}, false)
		})
	}
}

// With the denial and no tcpi_notsent_bytes, the methods that need unsent
// bytes fail with their own sentinel before any byte reaches the socket; the
// acknowledged wait still works.
func TestLinuxMethodsFailBeforeWritingWithoutSent(t *testing.T) {
	denyOUTQNSD(t, syscall.EACCES, 144)
	const cut = 40
	split := []Pos{{Offset: cut}}
	for _, tc := range []struct {
		name string
		opts Options
		want error
	}{
		{"fake first", Options{Fake: &FakeOptions{TTL: 4, Prefix: cut}}, ErrFakeUnsupported},
		{"fake after a piece", Options{Split: split, Fake: &FakeOptions{TTL: 4}}, ErrFakeUnsupported},
		{"fake after oob", Options{Split: split, OOB: &OOBOptions{}, Fake: &FakeOptions{TTL: 4}}, ErrFakeUnsupported},
		{"disorder", Options{Split: split, Disorder: true}, ErrDisorderUnsupported},
		{"disorder with fake", Options{Split: split, Disorder: true, Fake: &FakeOptions{TTL: 4}}, ErrDisorderUnsupported},
		{"wait sent", Options{Split: split, SplitWait: SplitWaitSent}, ErrSplitWaitUnsupported},
		{"wait sent with fake", Options{Split: split, SplitWait: SplitWaitSent, Fake: &FakeOptions{TTL: 4, Prefix: 2 * cut}}, ErrSplitWaitUnsupported},
	} {
		for _, network := range []string{"tcp4", "tcp6"} {
			t.Run(fmt.Sprintf("%s/%s", tc.name, network), func(t *testing.T) {
				if err := tc.opts.Validate(); err != nil {
					t.Fatalf("Validate: %v", err) // accepted: the socket decides
				}
				client, server := loopbackPair(t, network)
				w := WrapConn(client, tc.opts)
				_ = w.SetWriteDeadline(time.Now().Add(5 * time.Second))
				hello := captureHello(t, "example.test")
				n, err := w.Write(hello)
				if n != 0 || !errors.Is(err, tc.want) || !errors.Is(err, syscall.EACCES) {
					t.Fatalf("Write: %d %v, want 0 and %v", n, err, tc.want)
				}
				_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
				got, err := io.ReadAll(server)
				if err != nil || len(got) != 0 {
					t.Fatalf("server read %d bytes (%v) from a failed write", len(got), err)
				}
				if len(fakeSlots) != 0 {
					t.Fatalf("pending fake resources: %d", len(fakeSlots))
				}
			})
		}
	}
	t.Run("wait acked still works", func(t *testing.T) {
		socketMethodRoundTrip(t, "tcp4", Options{Split: []Pos{{Offset: 3}, {Offset: 1, FromSNI: true}}, SplitWait: SplitWaitAcked}, false)
	})
	t.Run("oob still works", func(t *testing.T) {
		socketMethodRoundTrip(t, "tcp4", Options{Split: []Pos{{Offset: 3}, {Offset: 1, FromSNI: true}}, OOB: &OOBOptions{}}, false)
	})
}

// requireNotsentBytes skips on a kernel without tcpi_notsent_bytes.
func requireNotsentBytes(t *testing.T) {
	t.Helper()
	client, _ := loopbackPair(t, "tcp4")
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ok bool
	var infoErr error
	if err := raw.Control(func(fd uintptr) {
		_, ok, infoErr = (&linuxAck{q: sockQuery{getsockopt: getsockoptBytes}}).notsent(fd)
	}); err != nil || infoErr != nil {
		t.Fatal(err, infoErr)
	}
	if !ok {
		t.Skip("kernel before 4.6: no tcpi_notsent_bytes")
	}
}
