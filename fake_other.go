//go:build !windows && !linux

package desync

const supportsFake = false

func (c *Conn) sendFakePiece(real, payload []byte, queued bool, rest func() error) error {
	return ErrFakeUnsupported
}

// fakeObservesSent is false: there is no fake here (see fake_linux.go).
const fakeObservesSent = false

func (c *Conn) prepareFake() error { return nil }
