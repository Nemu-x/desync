package desync

import "encoding/binary"

// struct tcp_info (include/uapi/linux/tcp.h) starts with eight __u8 fields
// and 24 __u32 fields, tcpi_total_retrans the last of them at offset 100.
// The __u64 fields follow at offset 104, which is 8-byte aligned, so neither
// 64-bit ABIs (__u64 aligned to 8) nor i386 (aligned to 4) insert padding:
// the layout is the same on every architecture, in native byte order.
//
//	104 tcpi_pacing_rate       __u64 (Linux 3.15)
//	112 tcpi_max_pacing_rate   __u64
//	120 tcpi_bytes_acked       __u64 (4.1)
//	128 tcpi_bytes_received    __u64 (4.1)
//	136 tcpi_segs_out          __u32 (4.2)
//	140 tcpi_segs_in           __u32
//	144 tcpi_notsent_bytes     __u32 (4.6)
//
// The kernel copies min(optlen, sizeof(struct tcp_info)) bytes and returns
// that length, so an older kernel answers with fewer than 148 bytes.
const (
	tcpInfoNotsentOffset = 144
	tcpInfoNotsentEnd    = tcpInfoNotsentOffset + 4
)

// parseTCPInfoNotsent returns tcpi_notsent_bytes from the first bytes of a
// tcp_info the kernel returned, or false when they end before the field.
func parseTCPInfoNotsent(b []byte, order binary.ByteOrder) (int64, bool) {
	if len(b) < tcpInfoNotsentEnd {
		return 0, false
	}
	return int64(order.Uint32(b[tcpInfoNotsentOffset:])), true
}
