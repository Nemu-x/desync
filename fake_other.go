//go:build !windows && !linux

package desync

const supportsFake = false

func (c *Conn) sendFake(real, payload, tail []byte) error { return ErrFakeUnsupported }
