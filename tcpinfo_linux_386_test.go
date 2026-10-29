//go:build linux && 386

package desync

import (
	"net"
	"testing"
)

// linux/386 reaches getsockopt through socketcall; the retransmission count
// is not read there.
func tcpRetransmits(testing.TB, *net.TCPConn) (uint32, bool) { return 0, false }
