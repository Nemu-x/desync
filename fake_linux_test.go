//go:build linux

package desync

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func openFDs(t testing.TB) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip(err)
	}
	return len(entries)
}

// dropLowHop makes the server's kernel discard every segment that arrives
// with a TTL or hop limit below 8, like a router on a real path would for a
// low-hop transmission. A classic BPF socket filter runs in tcp_v4_rcv /
// tcp_v6_rcv before TCP processing, so a dropped segment is never
// acknowledged and the client must retransmit it.
func dropLowHop(t *testing.T, server *net.TCPConn, ipv6 bool) {
	t.Helper()
	const skfNetOff = -0x100000 // linux/filter.h SKF_NET_OFF
	offset := 8                 // IPv4 TTL
	if ipv6 {
		offset = 7 // IPv6 hop limit
	}
	prog := []syscall.SockFilter{
		*syscall.LsfStmt(syscall.BPF_LD|syscall.BPF_B|syscall.BPF_ABS, skfNetOff+offset),
		*syscall.LsfJump(syscall.BPF_JMP|syscall.BPF_JGE|syscall.BPF_K, 8, 0, 1),
		*syscall.LsfStmt(syscall.BPF_RET|syscall.BPF_K, 0x40000),
		*syscall.LsfStmt(syscall.BPF_RET|syscall.BPF_K, 0),
	}
	raw, err := server.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var opErr error
	if err := raw.Control(func(fd uintptr) { opErr = syscall.AttachLsf(int(fd), prog) }); err != nil {
		t.Fatal(err)
	}
	if errors.Is(opErr, syscall.EPERM) && os.Getenv("DESYNC_REQUIRE_LOWHOP") == "" {
		// unprivileged users may not attach this filter on some kernels (the
		// GitHub runners); CI runs the test again as root with the variable set
		t.Skipf("attaching the drop filter: %v; run as root or set DESYNC_REQUIRE_LOWHOP=1 to fail instead", opErr)
	}
	if opErr != nil {
		t.Fatal(opErr)
	}
}

func linuxFakeRoundTrip(t *testing.T, network string, opts Options, drop bool) {
	client, server := loopbackPair(t, network)
	if drop {
		dropLowHop(t, server, network == "tcp6")
	}
	hello := captureHello(t, "example.test")
	wire := FragmentRecord(hello, resolve(opts.TLSRec, mustParse(t, hello), recordHeaderLen, len(hello)))
	if !drop && opts.Fake != nil && opts.Fake.Payload == nil {
		// Without drops the first transmission reaches the server: a fake
		// equal to the real bytes keeps that stream verifiable.
		opts.Fake.Payload = wire
	}
	tail := []byte("after the hello")
	want := append(append([]byte(nil), wire...), tail...)
	before := tcpHop(t, client)
	w := WrapConn(client, opts)
	_ = w.SetWriteDeadline(time.Now().Add(10 * time.Second))
	read := readUntil(server, tail)
	input := append(append([]byte(nil), hello...), tail...)
	if n, err := w.Write(input); err != nil || n != len(input) {
		t.Fatalf("Write: %d %v", n, err)
	}
	if got := <-read; !bytes.Equal(got, want) {
		t.Fatalf("server stream changed: got %d bytes, want %d\ngot  %q\nwant %q", len(got), len(want), got, want)
	}
	if after := tcpHop(t, client); after != before {
		t.Fatalf("hop limit not restored: %d -> %d", before, after)
	}
	if drop {
		if n, ok := tcpRetransmits(t, client); ok && n == 0 {
			t.Fatal("the low-hop transmission was not dropped and retransmitted")
		} else if ok {
			t.Logf("retransmitted segments: %d", n)
		}
	}
	if len(fakeSlots) != 0 {
		t.Fatalf("pending fake resources: %d", len(fakeSlots))
	}
}

func TestLinuxFakeNativeStream(t *testing.T) {
	fds := openFDs(t)
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, rec := range [][]Pos{nil, {{Offset: 1, FromSNI: true}}} {
			for _, prefix := range []int{-1, 1, 40} {
				t.Run(fmt.Sprintf("%s/tlsrec=%v/prefix=%d", network, rec, prefix), func(t *testing.T) {
					linuxFakeRoundTrip(t, network, Options{TLSRec: rec, Fake: &FakeOptions{TTL: 64, Prefix: prefix}}, false)
				})
			}
		}
	}
	// Fake with split pieces: the decoy equals the original piece (Payload
	// is the stream, Offset aligns it), so the undropped stream is checked.
	const cut = 40
	for name, opts := range map[string]Options{
		"split-fake":    {Split: []Pos{{Offset: cut}}, Fake: &FakeOptions{TTL: 64, Offset: cut}},
		"fake-split":    {Split: []Pos{{Offset: cut}, {Offset: 2 * cut}}, Fake: &FakeOptions{TTL: 64, Prefix: cut}},
		"disorder-fake": {Split: []Pos{{Offset: cut}}, Disorder: true, Fake: &FakeOptions{TTL: 64, Offset: cut}},
		"disoob-fake":   {Split: []Pos{{Offset: cut}}, Disorder: true, OOB: &OOBOptions{}, Fake: &FakeOptions{TTL: 64, Offset: cut}},
		"wait-fake":     {Split: []Pos{{Offset: cut}, {Offset: 3 * cut}}, SplitWait: SplitWaitSent, SplitDelay: time.Millisecond, Fake: &FakeOptions{TTL: 64, Prefix: 2 * cut, Offset: cut}},
	} {
		for _, network := range []string{"tcp4", "tcp6"} {
			opts := opts
			fake := *opts.Fake
			opts.Fake = &fake
			t.Run(name+"/"+network, func(t *testing.T) { linuxFakeRoundTrip(t, network, opts, false) })
		}
	}
	if after := openFDs(t); after > fds {
		t.Fatalf("file descriptors leaked: %d -> %d", fds, after)
	}
}

// The low-hop transmissions are really dropped here, so the stream is
// byte-identical only if TCP retransmitted the original bytes with the
// restored hop limit. For Fake the first transmission carries different
// bytes: the server never sees them, because the kernel's retransmission
// reads the overwritten page.
func TestLinuxLowHopDropRetransmitsOriginal(t *testing.T) {
	garbage := bytes.Repeat([]byte{'X'}, 600)
	split := []Pos{{Offset: 1, FromSNI: true}}
	rec := []Pos{{Offset: 3, FromSNI: true}}
	for name, opts := range map[string]Options{
		"fake":          {Fake: &FakeOptions{TTL: 3, Payload: garbage}},
		"fake-tlsrec":   {TLSRec: rec, Fake: &FakeOptions{TTL: 3, Payload: garbage, Prefix: 20}},
		"fake-template": {Fake: &FakeOptions{TTL: 3, Payload: defaultFakeTLS()}},
		"disorder":      {TLSRec: rec, Split: split, Disorder: true},
		"disoob":        {TLSRec: rec, Split: split, Disorder: true, OOB: &OOBOptions{}},
		// Fake combined with split pieces and the first-piece methods.
		"split-fake":      {Split: split, Fake: &FakeOptions{TTL: 3, Payload: garbage}},
		"fake-split":      {TLSRec: rec, Split: split, Fake: &FakeOptions{TTL: 3, Payload: garbage, Prefix: 20}},
		"split-fake-wait": {TLSRec: rec, Split: []Pos{{Offset: 3}, {Offset: 1, FromSNI: true}, {Offset: 40, FromSNI: true}}, SplitWait: SplitWaitSent, Fake: &FakeOptions{TTL: 3, Payload: garbage, Prefix: -5}},
		"random-fake":     {Random: &RandomOptions{Split: []RandomCut{{From: Pos{Offset: -8, FromSNI: true}, To: Pos{Offset: 8, FromSNI: true}, Count: 2, MinPiece: 2}}, Seed: 7}, Fake: &FakeOptions{TTL: 3, Payload: garbage}},
		"disorder-fake":   {Split: split, Disorder: true, Fake: &FakeOptions{TTL: 3, Payload: garbage}},
		"oob-fake":        {Split: split, OOB: &OOBOptions{}, Fake: &FakeOptions{TTL: 3, Payload: garbage}},
		"disoob-fake":     {TLSRec: rec, Split: split, Disorder: true, OOB: &OOBOptions{}, Fake: &FakeOptions{TTL: 3, Payload: garbage}},
		// Decoy ClientHellos with another server name.
		"fake-sni":       {Fake: &FakeOptions{TTL: 3, SNI: []string{"decoy.example", "*.?#.example"}, Randomize: true}},
		"fake-orig":      {Fake: &FakeOptions{TTL: 3, FromOriginal: true, SNI: []string{"decoy.example"}}},
		"split-fake-sni": {Split: split, Fake: &FakeOptions{TTL: 3, SNI: []string{"decoy.example"}, Offset: 7}},
	} {
		for _, network := range []string{"tcp4", "tcp6"} {
			opts := opts
			if opts.Fake != nil {
				fake := *opts.Fake
				opts.Fake = &fake
			}
			t.Run(name+"/"+network, func(t *testing.T) { linuxFakeRoundTrip(t, network, opts, true) })
			// The same with SIOCOUTQNSD denied as on Android: the transmission
			// is observed through TCP_INFO tcpi_notsent_bytes.
			t.Run("siocoutqnsd-denied/"+name+"/"+network, func(t *testing.T) {
				requireNotsentBytes(t)
				denyOUTQNSD(t, syscall.EACCES, -1)
				linuxFakeRoundTrip(t, network, opts, true)
			})
		}
	}
}

// fillSendQueue writes until the peer, which does not read, has a full
// receive window and the client's send buffer holds unsent bytes.
func fillSendQueue(t *testing.T, client, server *net.TCPConn) {
	t.Helper()
	_ = server.SetReadBuffer(4096)
	_ = client.SetWriteBuffer(4096)
	_ = client.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
	_, err := client.Write(make([]byte, 8<<20))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("filling the queue: %v", err)
	}
	_ = client.SetWriteDeadline(time.Time{})
}

// A blocked fake ends at the deadline, Fake.Timeout or Close, restores the
// hop limit and releases its page, pipe and slot.
func TestLinuxFakeBoundedWhenBlocked(t *testing.T) {
	fds := openFDs(t)
	for _, mode := range []string{"deadline", "timeout", "close"} {
		t.Run(mode, func(t *testing.T) {
			client, server := loopbackPair(t, "tcp4")
			fillSendQueue(t, client, server)
			before := tcpHop(t, client)
			opts := Options{Fake: &FakeOptions{TTL: 3, Timeout: time.Minute}}
			want := os.ErrDeadlineExceeded
			switch mode {
			case "timeout":
				opts.Fake.Timeout = 50 * time.Millisecond
			case "close":
				want = net.ErrClosed
			}
			w := WrapConn(client, opts).(*Conn)
			switch mode {
			case "deadline":
				_ = w.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
			case "close":
				time.AfterFunc(50*time.Millisecond, func() { w.Close() })
			}
			real := bytes.Repeat([]byte{'r'}, 300)
			start := time.Now()
			err := w.sendFake(real, bytes.Repeat([]byte{'f'}, 300), []byte("tail"))
			if !errors.Is(err, want) {
				t.Fatalf("sendFake: %v, want %v", err, want)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Fatalf("ended after %v", d)
			}
			if mode != "close" {
				if after := tcpHop(t, client); after != before {
					t.Fatalf("hop limit leaked: %d -> %d", before, after)
				}
			}
			if len(fakeSlots) != 0 {
				t.Fatalf("pending fake resources: %d", len(fakeSlots))
			}
		})
	}
	if after := openFDs(t); after > fds {
		t.Fatalf("file descriptors leaked: %d -> %d", fds, after)
	}
}

func TestLinuxFakeExpiredDeadlineAllocatesNothing(t *testing.T) {
	client, _ := loopbackPair(t, "tcp4")
	w := WrapConn(client, Options{Fake: &FakeOptions{TTL: 4}})
	_ = w.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := w.Write(captureHello(t, "example.test")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write: %v", err)
	}
	if len(fakeSlots) != 0 {
		t.Fatal("expired deadline allocated resources")
	}
}

func TestLinuxFakeBoundedResources(t *testing.T) {
	client, server := loopbackPair(t, "tcp4")
	go func() { _, _ = io.Copy(io.Discard, server) }()
	for i := 0; i < cap(fakeSlots); i++ {
		fakeSlots <- struct{}{}
	}
	defer func() {
		for len(fakeSlots) > 0 {
			<-fakeSlots
		}
	}()
	w := WrapConn(client, Options{Fake: &FakeOptions{TTL: 4}}).(*Conn)
	if err := w.sendFake([]byte("ab"), []byte("cd"), []byte("e")); !errors.Is(err, ErrFakeBusy) {
		t.Fatalf("resource limit: %v", err)
	}
}

// A prefix larger than one pipe needs several vmsplice/splice rounds.
func TestLinuxFakeLargePrefix(t *testing.T) {
	client, server := loopbackPair(t, "tcp4")
	real := bytes.Repeat([]byte("0123456789abcdef"), 20<<10) // 320 KiB
	tail := []byte("tail")
	got := make(chan []byte, 1)
	go func() {
		_ = server.SetReadDeadline(time.Now().Add(10 * time.Second))
		b := make([]byte, len(real)+len(tail))
		n, _ := io.ReadFull(server, b)
		got <- b[:n]
	}()
	before := tcpHop(t, client)
	w := WrapConn(client, Options{Fake: &FakeOptions{TTL: 64, Timeout: 5 * time.Second}}).(*Conn)
	if err := w.sendFake(real, real, tail); err != nil {
		t.Fatal(err)
	}
	if b := <-got; !bytes.Equal(b, append(append([]byte(nil), real...), tail...)) {
		t.Fatalf("stream changed: %d bytes", len(b))
	}
	if after := tcpHop(t, client); after != before {
		t.Fatalf("hop limit not restored: %d -> %d", before, after)
	}
}
