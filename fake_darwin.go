//go:build darwin

package desync

// fakeUnsupportedReason: the fake prefix needs the kernel's retransmission to
// carry the original bytes although the first transmission carried others.
// Linux gets that from splice, which queues references to a user page that
// is overwritten afterwards; Windows from TransmitFile reading a file whose
// cache is rewritten. xnu has no splice/vmsplice, and its sendfile copies the
// file data into the socket buffer (mbufs) before returning, so a later file
// change never reaches a retransmission: the server would receive the fake
// bytes. See docs/connection-io.md.
const fakeUnsupportedReason = "no splice: sendfile copies the data into the socket buffer, so a retransmission cannot carry the original bytes"
