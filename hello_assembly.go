package desync

import (
	"net"
	"time"
)

type helloAssembly struct {
	buf  []byte
	scan helloScanner
}

func (a *helloAssembly) append(p []byte, limit int) error {
	if len(p) > limit-len(a.buf) {
		return ErrClientHelloTooLarge
	}
	n := len(a.buf) + len(p)
	if n > cap(a.buf) {
		capacity := cap(a.buf) * 2
		if capacity < 64 {
			capacity = 64
		}
		if capacity < n {
			capacity = n
		}
		if capacity > limit {
			capacity = limit
		}
		grown := make([]byte, len(a.buf), capacity)
		copy(grown, a.buf)
		a.buf = grown
	}
	a.buf = append(a.buf, p...)
	return nil
}

func (a *helloAssembly) feed(p []byte, limits helloLimits) (int, helloFrame, error) {
	used := 0
	for len(p) > 0 {
		n := a.scan.need() - len(a.buf)
		if n > len(p) {
			n = len(p)
		}
		if err := a.append(p[:n], limits.wireSize()); err != nil {
			return used, helloFrame{}, err
		}
		used += n
		p = p[n:]
		f, err := a.scan.scan(a.buf, limits)
		if err != errShort {
			return used, f, err
		}
	}
	return used, helloFrame{}, errShort
}

// inspectHello borrows complete input directly. Only incomplete input uses
// the one bounded assembly buffer; a large coalesced tail is never copied in.
func (c *Conn) inspectHello(p []byte) (data, tail []byte, f helloFrame, buffered int, err error) {
	limits := c.opts.ClientHello.limits()
	if c.pending == nil {
		var scanner helloScanner
		f, err = scanner.scan(p, limits)
		if err == errShort {
			a := &helloAssembly{scan: scanner}
			if e := a.append(p, limits.wireSize()); e != nil {
				return nil, nil, f, 0, e
			}
			c.pending = a
			return nil, nil, f, 0, err
		}
		if err != nil {
			return p, nil, f, 0, err
		}
		return p[:f.wireLen], p[f.wireLen:], f, 0, nil
	}
	a := c.pending
	buffered = len(a.buf)
	var used int
	used, f, err = a.feed(p, limits)
	if err == errShort {
		return nil, nil, f, buffered, err
	}
	return a.buf, p[used:], f, buffered, err
}

// The watch is separate from the wire assembly, so retaining a timeout reason
// never retains a pointer back into its buffered wire data. deadlineMu guards it.
type helloWatch struct {
	timer  *time.Timer
	err    error
	active bool
}

func (c *Conn) beginHelloAssembly() error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.watch != nil {
		return c.watch.err
	}
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
	}
	w := &helloWatch{active: true}
	c.watch = w
	w.timer = time.AfterFunc(c.opts.ClientHello.limits().timeout, func() {
		c.deadlineMu.Lock()
		if c.watch != w || !w.active {
			c.deadlineMu.Unlock()
			return
		}
		w.active = false
		w.err = ErrClientHelloTimeout
		w.timer = nil
		c.deadlineMu.Unlock()
		_ = c.Close()
	})
	return nil
}

func (c *Conn) stopHelloAssembly() error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.stopHelloAssemblyLocked()
}

func (c *Conn) stopHelloAssemblyLocked() error {
	w := c.watch
	if w == nil {
		return nil
	}
	w.active = false
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
	if w.err == nil {
		c.watch = nil
	}
	return w.err
}

func (c *Conn) helloAssemblyError() error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.watch != nil {
		return c.watch.err
	}
	return nil
}

// Read remains independent of the writer lock. Closing incomplete assembly
// wakes a pending Read and preserves its actual timeout reason.
func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		if reason := c.helloAssemblyError(); reason != nil {
			return n, reason
		}
	}
	return n, err
}
