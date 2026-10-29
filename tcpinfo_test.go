package desync

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

// linuxTCPInfoHead mirrors struct tcp_info of include/uapi/linux/tcp.h up to
// tcpi_notsent_bytes. Go aligns uint64 to 4 bytes on 386 and arm and to 8
// elsewhere, like the C ABIs of those architectures (arm EABI aligns __u64
// to 8, which gives the same offsets here because 104 is a multiple of 8).
type linuxTCPInfoHead struct {
	state, caState, retransmits, probes, backoff, options, wscale, appLimited uint8

	rto, ato, sndMss, rcvMss                         uint32
	unacked, sacked, lost, retrans, fackets          uint32
	lastDataSent, lastAckSent, lastDataRecv, lastAck uint32
	pmtu, rcvSsthresh, rtt, rttvar, sndSsthresh      uint32
	sndCwnd, advmss, reordering, rcvRtt, rcvSpace    uint32
	totalRetrans                                     uint32

	pacingRate, maxPacingRate, bytesAcked, bytesReceived uint64
	segsOut, segsIn                                      uint32
	notsentBytes                                         uint32
}

func TestTCPInfoNotsentLayout(t *testing.T) {
	var h linuxTCPInfoHead
	if got := unsafe.Offsetof(h.totalRetrans); got != 100 {
		t.Fatalf("tcpi_total_retrans at %d, want 100", got)
	}
	if got := unsafe.Offsetof(h.pacingRate); got != 104 {
		t.Fatalf("tcpi_pacing_rate at %d, want 104 (no padding on any arch)", got)
	}
	if got := unsafe.Offsetof(h.notsentBytes); got != tcpInfoNotsentOffset {
		t.Fatalf("tcpi_notsent_bytes at %d, want %d", got, tcpInfoNotsentOffset)
	}
	if tcpInfoNotsentEnd != 148 {
		t.Fatalf("end %d", tcpInfoNotsentEnd)
	}
}

func TestParseTCPInfoNotsent(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		full := make([]byte, 280) // a 6.x kernel's tcp_info is longer
		for i := range full {
			full[i] = 0xEE // every other field is noise
		}
		order.PutUint32(full[tcpInfoNotsentOffset:], 0x01020304)
		for _, tc := range []struct {
			name string
			n    int
			want int64
			ok   bool
		}{
			{"6.x kernel", 280, 0x01020304, true},
			{"4.6 kernel, 160 bytes", 160, 0x01020304, true},
			{"exactly up to the field", 148, 0x01020304, true},
			{"field cut short", 147, 0, false},
			{"4.2-4.5 kernel (segs_in last)", 144, 0, false},
			{"4.1 kernel (bytes_received last)", 136, 0, false},
			{"3.15 kernel (max_pacing_rate last)", 120, 0, false},
			{"syscall.TCPInfo size", 104, 0, false},
			{"empty", 0, 0, false},
		} {
			got, ok := parseTCPInfoNotsent(full[:tc.n], order)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("%v %s: %#x %v, want %#x %v", order, tc.name, got, ok, tc.want, tc.ok)
			}
		}
		order.PutUint32(full[tcpInfoNotsentOffset:], 0xFFFFFFFF)
		if got, ok := parseTCPInfoNotsent(full, order); !ok || got != 0xFFFFFFFF {
			t.Fatalf("%v: large value %d %v", order, got, ok)
		}
	}
}
