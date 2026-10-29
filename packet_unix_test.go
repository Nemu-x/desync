//go:build linux || darwin

package desync

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

func udpSocketTTL(c *net.UDPConn) (int, error) {
	return udpSocketTTLFor(c, c.LocalAddr().(*net.UDPAddr).IP)
}

func udpSocketTTLFor(c *net.UDPConn, destination net.IP) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var value int
	var operationErr error
	err = raw.Control(func(fd uintptr) {
		var h savedHop
		h, operationErr = hopFor(fd, destination)
		value = h.restore
	})
	return value, errors.Join(err, operationErr)
}

type udpRecordedWrite struct {
	ttl  int
	data []byte
}
type udpRecordingConn struct {
	*net.UDPConn
	writes   []udpRecordedWrite
	failFake bool
}

func (c *udpRecordingConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	ttl, err := udpSocketTTLFor(c.UDPConn, addr.(*net.UDPAddr).IP)
	if err != nil {
		return 0, err
	}
	c.writes = append(c.writes, udpRecordedWrite{ttl: ttl, data: append([]byte(nil), p...)})
	if c.failFake && ttl == 4 {
		return 0, errors.New("injected send failure")
	}
	return c.UDPConn.WriteTo(p, addr)
}

func TestUDPFakeNativeOrderSourcePortTTLAndConcurrentWrites(t *testing.T) {
	for _, tc := range []struct{ network, address, serverNetwork, serverAddress string }{{"udp4", "127.0.0.1:0", "udp4", "127.0.0.1:0"}, {"udp6", "[::1]:0", "udp6", "[::1]:0"}, {"udp", "[::]:0", "udp4", "127.0.0.1:0"}} {
		t.Run(tc.network, func(t *testing.T) {
			server, err := net.ListenPacket(tc.serverNetwork, tc.serverAddress)
			if err != nil {
				if tc.network == "udp6" {
					t.Skip(err)
				}
				t.Fatal(err)
			}
			defer server.Close()
			client, err := net.ListenPacket(tc.network, tc.address)
			if err != nil {
				t.Fatal(err)
			}
			recorder := &udpRecordingConn{UDPConn: client.(*net.UDPConn)}
			originalTTL, err := udpSocketTTLFor(recorder.UDPConn, server.LocalAddr().(*net.UDPAddr).IP)
			if err != nil {
				t.Fatal(err)
			}
			fakePayload := []byte("fake-datagram")
			wrapped, err := WrapPacketConn(recorder, UDPOptions{TTL: 4, Repeats: 2, Packets: 3, Payload: fakePayload})
			if err != nil {
				client.Close()
				t.Fatal(err)
			}
			defer wrapped.Close()
			fakePayload[0] = 'X' // options must own the buffer
			const originals = 20
			var writers sync.WaitGroup
			for i := 0; i < originals; i++ {
				writers.Add(1)
				go func() {
					defer writers.Done()
					if _, err := wrapped.WriteTo([]byte("original-datagram"), server.LocalAddr()); err != nil {
						t.Error(err)
					}
				}()
			}
			writers.Wait()
			if ttl, err := udpSocketTTLFor(recorder.UDPConn, server.LocalAddr().(*net.UDPAddr).IP); err != nil || ttl != originalTTL {
				t.Fatalf("TTL leaked: %d want %d: %v", ttl, originalTTL, err)
			}
			if len(recorder.writes) != originals+6 {
				t.Fatalf("unbounded or missing injections: %d", len(recorder.writes))
			}
			if !bytes.Equal(recorder.writes[0].data, []byte("fake-datagram")) {
				t.Fatal("first packet was not the independent fake payload")
			}
			for _, write := range recorder.writes {
				want := originalTTL
				if bytes.Equal(write.data, []byte("fake-datagram")) {
					want = 4
				} else if !bytes.Equal(write.data, []byte("original-datagram")) {
					t.Fatalf("application payload changed: %q", write.data)
				}
				if write.ttl != want {
					t.Fatalf("wrong TTL at actual UDP write: %d want %d", write.ttl, want)
				}
			}
			if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			for i, write := range recorder.writes {
				buf := make([]byte, 256)
				n, source, err := server.ReadFrom(buf)
				if err != nil {
					t.Fatal(err)
				}
				if source.(*net.UDPAddr).Port != client.LocalAddr().(*net.UDPAddr).Port || !bytes.Equal(buf[:n], write.data) {
					t.Fatalf("datagram %d/order/source changed: %s %q", i, source, buf[:n])
				}
			}
			stats := wrapped.Counters()
			if stats.Packets != originals || stats.FakePackets != 6 || stats.FakeErrors != 0 || stats.Peers != 1 {
				t.Fatalf("wrong counters: %+v", stats)
			}
		})
	}
}

func TestUDPFakeRestoresTTLOnFailureAndDeadlineRecovery(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	recorder := &udpRecordingConn{UDPConn: client.(*net.UDPConn), failFake: true}
	originalTTL, err := udpSocketTTL(recorder.UDPConn)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := WrapPacketConn(recorder, UDPOptions{TTL: 4, Repeats: 1, Packets: 3})
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	defer wrapped.Close()
	if _, err := wrapped.WriteTo([]byte("original"), server.LocalAddr()); err == nil {
		t.Fatal("lost fake send failure")
	}
	if ttl, err := udpSocketTTL(recorder.UDPConn); err != nil || ttl != originalTTL {
		t.Fatalf("failure leaked TTL: %d %v", ttl, err)
	}
	recorder.failFake = false
	if err := wrapped.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := wrapped.WriteTo([]byte("original"), server.LocalAddr()); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("lost deadline: %v", err)
	}
	if ttl, err := udpSocketTTL(recorder.UDPConn); err != nil || ttl != originalTTL {
		t.Fatalf("deadline leaked TTL: %d %v", ttl, err)
	}
	if err := wrapped.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := wrapped.WriteTo([]byte("original"), server.LocalAddr()); err != nil {
		t.Fatalf("deadline could not be reset: %v", err)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := wrapped.WriteTo([]byte("original"), server.LocalAddr()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("lost Close: %v", err)
	}
}

func TestUDPPeerTrackingIsBounded(t *testing.T) {
	c := &PacketConn{opts: UDPOptions{Packets: 1, Counters: &UDPCounters{}}, peers: make(map[netip.AddrPort]udpPeer)}
	for i := 1; i <= 64; i++ {
		if !c.shouldInject(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000 + i}) {
			t.Fatal("missing peer")
		}
	}
	if c.shouldInject(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9000}) || len(c.peers) != 64 {
		t.Fatal("peer map is not bounded")
	}
	for peer, state := range c.peers {
		state.last = time.Now().Add(-3 * time.Minute)
		c.peers[peer] = state
	}
	if !c.shouldInject(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9000}) || len(c.peers) != 1 {
		t.Fatal("expired peers were not reclaimed")
	}
}
