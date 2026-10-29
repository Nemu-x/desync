//go:build windows

package desync

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

type tailObservedTCPConn struct {
	*net.TCPConn
	tailStarted chan struct{}
	once        sync.Once
}

func (c *tailObservedTCPConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.tailStarted) })
	return c.TCPConn.Write(p)
}

// A pending TransmitFile must not prevent submission of the normal tail.
// A small TCP window makes the native request genuinely pending; the peer
// starts draining it only once the tail's Write has been entered.
func TestWindowsFakeSendsTailBeforeCompletion(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	raw, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	peer, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	tcp := raw.(*net.TCPConn)
	if err := tcp.SetWriteBuffer(0); err != nil {
		t.Fatal(err)
	}
	if err := peer.(*net.TCPConn).SetReadBuffer(1024); err != nil {
		t.Fatal(err)
	}
	observed := &tailObservedTCPConn{TCPConn: tcp, tailStarted: make(chan struct{})}
	w := WrapConn(observed, Options{Fake: &FakeOptions{TTL: 64, Timeout: time.Second}}).(*Conn)
	_ = w.SetDeadline(time.Now().Add(5 * time.Second))
	real := bytes.Repeat([]byte{'x'}, 512<<10)
	tail := []byte("LAST")
	serverErr := make(chan error, 1)
	go func() {
		select {
		case <-observed.tailStarted:
		case <-time.After(2 * time.Second):
			serverErr <- errors.New("tail was held behind TransmitFile completion")
			return
		}
		_ = peer.(*net.TCPConn).SetReadBuffer(1 << 20)
		_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, len(real)+len(tail))
		_, err := io.ReadFull(peer, got)
		if err == nil && (!bytes.Equal(got[:len(real)], real) || !bytes.Equal(got[len(real):], tail)) {
			err = errors.New("fake prefix/tail stream changed")
		}
		serverErr <- err
	}()
	if err := w.sendFake(real, real, tail); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func socketTTL(t *testing.T, c *net.TCPConn) int {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ttl int
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		ttl, optionErr = getsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL)
	}); err != nil {
		t.Fatal(err)
	}
	if optionErr != nil {
		t.Fatal(optionErr)
	}
	return ttl
}

func nativeFakeRoundTrip(t *testing.T, withTLSRec bool) {
	t.Helper()
	rec := captureHello(t, "example.test")
	opts := Options{Fake: &FakeOptions{TTL: 64, Prefix: -1}}
	wire := append([]byte(nil), rec...)
	if withTLSRec {
		opts.TLSRec = []Pos{{Offset: 1, FromSNI: true}}
		h, _ := ParseHello(rec)
		wire = FragmentRecord(rec, resolve(opts.TLSRec, h, recordHeaderLen, len(rec)))
	}
	// On loopback, low TTL does not expire. Use identical fake/original bytes
	// to exercise native I/O and lifetime handling without corrupting a peer.
	opts.Fake.Payload = wire
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	want := append(append([]byte(nil), wire...), []byte("AFTER")...)
	serverErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, len(want))
		_, err = io.ReadFull(c, got)
		if err == nil && !bytes.Equal(got, want) {
			err = fmt.Errorf("native stream changed: %d bytes", len(got))
		}
		serverErr <- err
	}()
	raw, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tcp := raw.(*net.TCPConn)
	before := socketTTL(t, tcp)
	w := WrapConn(tcp, opts)
	_ = w.SetDeadline(time.Now().Add(5 * time.Second))
	if n, err := w.Write(nil); n != 0 || err != nil {
		t.Fatalf("empty Write: %d %v", n, err)
	}
	if _, err := w.Write(rec); err != nil {
		t.Fatal(err)
	}
	if after := socketTTL(t, tcp); after != before {
		t.Fatalf("TTL changed: %d -> %d", before, after)
	}
	if _, err := w.Write([]byte("AFTER")); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestWindowsFakeNativeStream(t *testing.T) {
	t.Run("fake", func(t *testing.T) { nativeFakeRoundTrip(t, false) })
	t.Run("tlsrec-and-fake", func(t *testing.T) { nativeFakeRoundTrip(t, true) })
	if len(fakeSlots) != 0 {
		t.Fatalf("pending resources: %d", len(fakeSlots))
	}
}

func TestWindowsFakeConcurrentNativeStream(t *testing.T) {
	for i := 0; i < 8; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) { t.Parallel(); nativeFakeRoundTrip(t, true) })
	}
	t.Cleanup(func() {
		if len(fakeSlots) != 0 {
			t.Errorf("pending resources after parallel tests: %d", len(fakeSlots))
		}
	})
}

// The test supplies the actual outgoing hello as the fake payload so a
// loopback server can finish TLS. DPI effectiveness is tested in Sandbox.
type samePayloadTLSConn struct{ *Conn }

func (c *samePayloadTLSConn) Write(p []byte) (int, error) {
	if !c.done {
		h, err := ParseHello(p)
		if err == nil {
			c.opts.Fake.Payload = FragmentRecord(p[:h.RecordLen], resolve(c.opts.TLSRec, h, recordHeaderLen, h.RecordLen))
		}
	}
	return c.Conn.Write(p)
}

func TestWindowsFakeTLSHandshake(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cert := selfSigned(t)
	serverErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
		err = s.Handshake()
		if err == nil {
			_, err = s.Write([]byte("ok"))
		}
		serverErr <- err
	}()
	raw, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	w := WrapConn(raw, Options{TLSRec: []Pos{{Offset: 1, FromSNI: true}}, Fake: &FakeOptions{TTL: 64, Prefix: -1}}).(*Conn)
	_ = w.SetDeadline(time.Now().Add(5 * time.Second))
	client := tls.Client(&samePayloadTLSConn{w}, &tls.Config{ServerName: "www.youtube.com", InsecureSkipVerify: true})
	defer client.Close()
	var got [2]byte
	if _, err := io.ReadFull(client, got[:]); err != nil || string(got[:]) != "ok" {
		t.Fatalf("TLS: %q %v", got, err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestWindowsFakeExpiredDeadline(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	raw, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	peer, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	w := WrapConn(raw, Options{Fake: &FakeOptions{TTL: 4}})
	_ = w.SetWriteDeadline(time.Now().Add(-time.Second))
	_, err = w.Write(captureHello(t, "example.test"))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	if _, err := w.Write([]byte("later")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("later Write: %v", err)
	}
	if len(fakeSlots) != 0 {
		t.Fatal("expired deadline allocated native resources")
	}
}

func TestWindowsFakeBoundedResources(t *testing.T) {
	if len(fakeSlots) != 0 {
		t.Fatal("resources pending before test")
	}
	var ops []*nativeFake
	defer func() {
		for _, op := range ops {
			op.cleanup()
		}
	}()
	for i := 0; i < cap(fakeSlots); i++ {
		op, err := newNativeFake([]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		ops = append(ops, op)
		if op.overlap.HEvent&1 == 0 {
			t.Fatal("foreign IOCP notification is enabled")
		}
	}
	if _, err := newNativeFake([]byte{1}); !errors.Is(err, ErrFakeBusy) {
		t.Fatalf("resource limit: %v", err)
	}
}

func TestWindowsFakeQueuedCancellation(t *testing.T) {
	for _, mode := range []string{"deadline", "close"} {
		t.Run(mode, func(t *testing.T) {
			if len(fakeTransmitSlots) != 0 {
				t.Fatal("pending native transmissions before test")
			}
			fakeTransmitSlots <- struct{}{}
			fakeTransmitSlots <- struct{}{}
			defer func() { <-fakeTransmitSlots; <-fakeTransmitSlots }()
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			raw, err := net.Dial("tcp4", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			peer, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			w := WrapConn(raw, Options{Fake: &FakeOptions{TTL: 4}})
			rec := captureHello(t, "example.test")
			if mode == "deadline" {
				_ = w.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
			}
			done := make(chan error, 1)
			go func() { _, err := w.Write(rec); done <- err }()
			if mode == "close" {
				time.Sleep(5 * time.Millisecond)
				_ = w.Close()
			}
			select {
			case err := <-done:
				want := error(os.ErrDeadlineExceeded)
				if mode == "close" {
					want = net.ErrClosed
				}
				if !errors.Is(err, want) {
					t.Fatalf("queued %s: %v", mode, err)
				}
			case <-time.After(time.Second):
				t.Fatal("queued fake was not interrupted")
			}
			if len(fakeSlots) != 0 {
				t.Fatal("queued operation allocated native resources")
			}
		})
	}
}

// Fake combined with Split, Disorder and OOB on the native backend. On
// loopback the low TTL does not expire, so the decoy is the original piece
// itself (Payload is the stream, Offset aligns it with the piece).
func TestWindowsFakeSplitNativeStream(t *testing.T) {
	hello := captureHello(t, "example.test")
	const cut = 40
	for name, opts := range map[string]Options{
		"split-fake":      {Split: []Pos{{Offset: cut}}, Fake: &FakeOptions{TTL: 64, Offset: cut}},
		"fake-split":      {Split: []Pos{{Offset: cut}, {Offset: 2 * cut}}, Fake: &FakeOptions{TTL: 64, Prefix: cut}},
		"split-fake-wait": {Split: []Pos{{Offset: cut}, {Offset: len(hello) - 5}}, SplitWait: SplitWaitSent, SplitDelay: time.Millisecond, Fake: &FakeOptions{TTL: 64, Prefix: 2 * cut, Offset: cut}},
		"disorder-fake":   {Split: []Pos{{Offset: cut}}, Disorder: true, Fake: &FakeOptions{TTL: 64, Offset: cut}},
		"oob-fake":        {Split: []Pos{{Offset: cut}}, OOB: &OOBOptions{}, Fake: &FakeOptions{TTL: 64, Offset: cut}},
		"disoob-fake":     {Split: []Pos{{Offset: cut}}, Disorder: true, OOB: &OOBOptions{}, Fake: &FakeOptions{TTL: 64, Offset: cut}},
	} {
		opts := opts
		t.Run(name, func(t *testing.T) {
			fake := *opts.Fake
			fake.Payload = hello
			opts.Fake = &fake
			client, server := loopbackPair(t, "tcp4")
			before := socketTTL(t, client)
			w := WrapConn(client, opts)
			_ = w.SetWriteDeadline(time.Now().Add(5 * time.Second))
			tail := []byte("AFTER")
			read := readUntil(server, tail)
			if _, err := w.Write(append(append([]byte(nil), hello...), tail...)); err != nil {
				t.Fatal(err)
			}
			if got := <-read; !bytes.Equal(got, append(append([]byte(nil), hello...), tail...)) {
				t.Fatalf("server stream changed: %d bytes", len(got))
			}
			if after := socketTTL(t, client); after != before {
				t.Fatalf("TTL changed: %d -> %d", before, after)
			}
		})
	}
	if len(fakeSlots) != 0 {
		t.Fatalf("pending resources: %d", len(fakeSlots))
	}
}
