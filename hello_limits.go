package desync

import (
	"errors"
	"fmt"
	"os"
	"time"
)

const (
	DefaultMaxClientHelloSize    = 64 << 10
	DefaultMaxClientHelloRecords = 256
	DefaultClientHelloTimeout    = 5 * time.Second
	maxClientHelloSize           = 1 << 20
	maxClientHelloRecords        = 4096
	maxClientHelloTimeout        = time.Minute
)

var (
	ErrClientHelloTooLarge             = errors.New("desync: ClientHello exceeds configured size limit")
	ErrTooManyClientHelloRecords       = errors.New("desync: ClientHello exceeds configured record limit")
	ErrClientHelloTimeout        error = &clientHelloTimeoutError{}
)

type clientHelloTimeoutError struct{}

func (*clientHelloTimeoutError) Error() string {
	return "desync: incomplete ClientHello assembly timed out"
}
func (*clientHelloTimeoutError) Timeout() bool   { return true }
func (*clientHelloTimeoutError) Temporary() bool { return false }
func (*clientHelloTimeoutError) Unwrap() error   { return os.ErrDeadlineExceeded }

// ClientHelloOptions bounds first-handshake assembly. Zero fields use the
// defaults above. The options apply only when a transformation is enabled.
type ClientHelloOptions struct {
	// MaxSize includes the four-byte handshake header; valid range 4..1 MiB.
	MaxSize int
	// MaxRecords bounds input records through the end of the hello (1..4096).
	MaxRecords int
	// Timeout bounds incomplete assembly, not socket transmission. It starts
	// with the first accepted incomplete write and is never extended by input.
	// The valid range is positive through one minute; zero defaults to 5 s.
	Timeout time.Duration
}

type helloLimits struct {
	size, records int
	timeout       time.Duration
}

func (o *ClientHelloOptions) limits() helloLimits {
	l := helloLimits{DefaultMaxClientHelloSize, DefaultMaxClientHelloRecords, DefaultClientHelloTimeout}
	if o != nil {
		if o.MaxSize != 0 {
			l.size = o.MaxSize
		}
		if o.MaxRecords != 0 {
			l.records = o.MaxRecords
		}
		if o.Timeout != 0 {
			l.timeout = o.Timeout
		}
	}
	return l
}

func (o *ClientHelloOptions) validate() error {
	l := o.limits()
	if l.size < 4 || l.size > maxClientHelloSize {
		return fmt.Errorf("desync: ClientHello max size must be between 4 and %d", maxClientHelloSize)
	}
	if l.records < 1 || l.records > maxClientHelloRecords {
		return fmt.Errorf("desync: ClientHello max records must be between 1 and %d", maxClientHelloRecords)
	}
	if l.timeout <= 0 || l.timeout > maxClientHelloTimeout {
		return fmt.Errorf("desync: ClientHello timeout must be positive and at most %s", maxClientHelloTimeout)
	}
	return nil
}

// The final record may contain bytes after the handshake. Allow its complete
// payload, plus bounded original record headers, without buffering the tail
// of the caller's Write beyond that record.
func (l helloLimits) wireSize() int { return l.size + maxRecordPayload + recordHeaderLen*l.records }
