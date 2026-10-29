//go:build !windows && !linux

package desync

const supportsFake = false

func (c *Conn) sendFakePiece(real, payload []byte, queued bool, rest func() error) error {
	return ErrFakeUnsupported
}
