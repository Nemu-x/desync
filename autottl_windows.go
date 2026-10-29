//go:build windows

package desync

// Winsock returns received-TTL control data only to WSARecvMsg, which, like
// IP_RECVTTL and IPV6_RECVHOPLIMIT, is limited to datagram and raw sockets,
// and SIO_TCP_INFO (TCP_INFO_v0/v1) has no TTL field.
const autoTTLReason = "Winsock reports a received TTL only through WSARecvMsg control data, which datagram and raw sockets get (IP_RECVTTL/IPV6_RECVHOPLIMIT); SIO_TCP_INFO has no TTL field"
