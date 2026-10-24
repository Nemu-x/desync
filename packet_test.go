package desync

import (
	"errors"
	"net"
	"testing"
)

func TestUDPValidationAndPlatform(t *testing.T) {
	for _, opts := range []UDPOptions{{TTL: 0}, {TTL: 256}, {TTL: 4, Repeats: -1}, {TTL: 4, Repeats: 17}, {TTL: 4, Packets: -1}, {TTL: 4, Packets: 9}, {TTL: 4, Payload: make([]byte, 1201)}} {
		if err := opts.Validate(); err == nil {
			t.Fatalf("accepted invalid UDP options: %+v", opts)
		}
	}
	if err := (UDPOptions{TTL: 4}).Validate(); SupportsUDPFake() && err != nil || !SupportsUDPFake() && !errors.Is(err, ErrUDPFakeUnsupported) {
		t.Fatalf("platform availability mismatch: %v", err)
	}
	if SupportsUDPFake() {
		if _, err := WrapPacketConn(nil, UDPOptions{TTL: 4}); !errors.Is(err, ErrUDPFakeRequiresSocket) {
			t.Fatal(err)
		}
		c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := WrapPacketConn(c, UDPOptions{TTL: 4}); !errors.Is(err, ErrUDPFakeRequiresSocket) {
			t.Fatalf("accepted connected UDP: %v", err)
		}
	}
}
