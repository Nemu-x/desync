//go:build !windows

package desync

const supportsFake = false

func (c *Conn) sendFake(real, payload, tail []byte) error { return ErrFakeUnsupported }
