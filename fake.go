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
	// ErrFakeFirstPiece reports that, for this ClientHello, the fake piece
	// would be the first TCP piece, which Disorder or OOB already sends. It
	// is returned before any byte is written.
	ErrFakeFirstPiece = errors.New("desync: the fake piece is the first TCP piece, which Disorder/OOB send; add a split position before the fake prefix")
)

// FakeOptions changes one TCP piece's initial transmission to low-TTL decoy
// bytes while retaining the original piece for TCP retransmission. It does
// not insert bytes into the application's stream. Implemented on Windows and
// Linux (including Android); see PlatformCapabilities for the macOS reason.
//
// Without Split the fake piece is the prefix [0, Prefix). With Split or
// Random.Split positions the prefix end is one more cut, and the fake piece
// is the piece that ends there (ByeDPI --fake as one of several parts): the
// pieces before it and after it are ordinary writes, Disorder/OOB still act
// on the first piece, and SplitDelay/SplitWaitSent apply between pieces.
type FakeOptions struct {
	// TTL expires the fake before the server (1..255). With AutoTTL it is
	// the fallback used when the path cannot be observed; 0 then fails the
	// write instead.
	TTL int
	// AutoTTL derives the TTL from the TTL of the server's packets on this
	// connection (see AutoTTL, ControlAutoTTL and
	// PlatformCapabilities().AutoTTL).
	AutoTTL *AutoTTL
	// Prefix is the end of the fake piece, measured after TLS record
	// fragmentation. Negative offsets count from the end; zero defaults to
	// -1 (all but the last byte).
	Prefix int
	// Payload defaults to ByeDPI v0.17.3's MIT-licensed TLS template.
	// It is zero-padded or truncated to the fake piece's length.
	Payload []byte
	// Timeout defaults to 3 seconds for native queue/completion waits.
	// Normal tail writes obey the connection's write deadline. A deadline on
	// the wrapper can shorten native waits; Close interrupts them.
	Timeout time.Duration

	// Decoy ClientHello (ByeDPI --fake-sni, --fake-tls-mod, --fake-offset).
	// With any of SNI, FromOriginal or Randomize the decoy is re-encoded per
	// connection as a valid ClientHello with every length recomputed, then
	// padded/truncated to the fake piece like Payload.

	// SNI replaces the decoy's server name. With several names one is drawn
	// per connection. In a name '*' becomes a random letter or digit, '?' a
	// random letter and '#' a random digit. Names must be DNS host names
	// (at most 64 names). A template's padding extension absorbs the length
	// change, so the template keeps its 517 bytes.
	SNI []string
	// FromOriginal builds the decoy from the connection's own ClientHello
	// (ByeDPI --fake-tls-mod orig) instead of Payload or the template. It
	// needs SNI or Randomize and excludes Payload.
	FromOriginal bool
	// Randomize replaces the decoy's random, session ID and key share values
	// with fresh random bytes per connection (ByeDPI --fake-tls-mod rand).
	// It needs a ClientHello decoy (the template, a ClientHello Payload or
	// FromOriginal).
	Randomize bool
	// Offset starts the decoy transmission at this byte of the decoy
	// (ByeDPI --fake-offset), for example to align a decoy with a fake
	// piece that does not start the stream. 0 starts at its first byte.
	Offset int
}

// SupportsFake reports platform availability, not effectiveness on a network.
func SupportsFake() bool { return supportsFake }

func (o Options) Validate() error {
	if o.SplitDelay < 0 {
		return fmt.Errorf("desync: split delay must not be negative")
	}
	if err := o.ClientHello.validate(); err != nil {
		return err
	}
	if err := o.Random.validate(o.ClientHello.limits()); err != nil {
		return err
	}
	if err := o.validateSplitWait(); err != nil {
		return err
	}
	if err := o.validateSocketMethods(); err != nil {
		return err
	}
	if o.Fake == nil {
		return nil
	}
	if err := o.Fake.validateTTL(); err != nil {
		return err
	}
	if o.Fake.Timeout < 0 {
		return fmt.Errorf("desync: fake timeout must not be negative")
	}
	if err := o.Fake.validateDecoy(); err != nil {
		return err
	}
	if o.splits() && o.SplitWait == SplitWaitAcked {
		// The low-hop fake piece is acknowledged only after its
		// retransmission, so the wait after it would last a retransmission
		// timeout and undo the order the fake relies on.
		return fmt.Errorf("desync: fake cannot be combined with SplitWaitAcked")
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
	return fakeBytes(data, 0, size)
}

// sendFake sends real as the fake piece and then tail as an ordinary write.
func (c *Conn) sendFake(real, payload, tail []byte) error {
	return c.sendFakePiece(real, payload, false, func() error {
		if err := writeAll(c.Conn, tail); err != nil {
			return fmt.Errorf("desync: TCP fake: write original tail: %w", err)
		}
		return nil
	})
}

func (c *Conn) fakeAbort(start time.Time) error {
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
	}
	timeout := c.fakeTimeout()
	c.deadlineMu.Lock()
	deadline := c.writeDeadline
	c.deadlineMu.Unlock()
	now := time.Now()
	if now.Sub(start) >= timeout || (!deadline.IsZero() && !now.Before(deadline)) {
		return os.ErrDeadlineExceeded
	}
	return nil
}

// fakeTimeout is Fake.Timeout or its 3-second default.
func (c *Conn) fakeTimeout() time.Duration {
	if c.opts.Fake.Timeout == 0 {
		return 3 * time.Second
	}
	return c.opts.Fake.Timeout
}
