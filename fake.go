package desync

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

var (
	ErrFakeUnsupported = errors.New("desync: TCP fake is not implemented on this platform")
	ErrFakeRequiresTCP = errors.New("desync: TCP fake requires a connection exposing SyscallConn")
	ErrFakeBusy        = errors.New("desync: too many pending TCP fake operations")
)

// FakeOptions changes a prefix's initial transmission to low-TTL bytes while
// retaining the original prefix for TCP retransmission. It does not insert
// bytes into the application's stream. Currently implemented on Windows.
type FakeOptions struct {
	TTL int
	// Prefix is measured after TLS record fragmentation. Negative offsets
	// count from the end; zero defaults to -1 (all but the last byte).
	Prefix int
	// Payload defaults to ByeDPI v0.17.3's MIT-licensed TLS template.
	// It is zero-padded or truncated to the selected prefix length.
	Payload []byte
	// Timeout defaults to 3 seconds for native queue/completion waits.
	// Normal tail writes obey the connection's write deadline. A deadline on
	// the wrapper can shorten native waits; Close interrupts them.
	Timeout time.Duration
}

// SupportsFake reports platform availability, not effectiveness on a network.
func SupportsFake() bool { return supportsFake }

func (o Options) Validate() error {
	if o.Fake == nil {
		return nil
	}
	if o.Fake.TTL < 1 || o.Fake.TTL > 255 {
		return fmt.Errorf("desync: fake TTL must be between 1 and 255")
	}
	if o.Fake.Timeout < 0 {
		return fmt.Errorf("desync: fake timeout must not be negative")
	}
	if len(o.Split) > 0 {
		return fmt.Errorf("desync: fake and TCP split cannot be combined yet")
	}
	if !SupportsFake() {
		return ErrFakeUnsupported
	}
	return nil
}

func fakePrefixLength(size, pos int) (int, error) {
	if pos == 0 {
		pos = -1
	}
	if pos < 0 {
		pos += size
	}
	if pos <= 0 || pos >= size {
		return 0, fmt.Errorf("desync: fake prefix must leave at least one original byte")
	}
	return pos, nil
}

func fakePayload(data []byte, size int) []byte {
	if len(data) == 0 {
		data = defaultFakeTLS()
	}
	out := make([]byte, size)
	copy(out, data)
	return out
}

func (c *Conn) fakeAbort(start time.Time) error {
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
	}
	timeout := c.opts.Fake.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	c.deadlineMu.Lock()
	deadline := c.writeDeadline
	c.deadlineMu.Unlock()
	now := time.Now()
	if now.Sub(start) >= timeout || (!deadline.IsZero() && !now.Before(deadline)) {
		return os.ErrDeadlineExceeded
	}
	return nil
}
