package desync

import (
	"net"
	"sync"
	"time"
)

// Options selects what happens to the first TLS record (the ClientHello) of a
// connection. Everything after it is passed through untouched, and a
// connection that does not start with a ClientHello is never modified.
type Options struct {
	// TLSRec splits the ClientHello into separate TLS records at these
	// positions (ByeDPI --tlsrec).
	TLSRec []Pos
	// Split sends the (possibly record-split) ClientHello in separate TCP
	// writes, cut at these positions of the original record (ByeDPI --split).
	Split []Pos
	// SplitDelay is a pause between the TCP pieces; 0 sends them back to back.
	SplitDelay time.Duration
}

// Enabled reports whether the options change anything.
func (o Options) Enabled() bool { return len(o.TLSRec) > 0 || len(o.Split) > 0 }

// Conn applies Options to the first record written to an underlying conn.
type Conn struct {
	net.Conn
	opts Options

	mu   sync.Mutex
	done bool   // first record handled (or not a ClientHello)
	buf  []byte // a ClientHello written in pieces, until it is complete
}

// WrapConn returns c with the options applied, or c itself when they are
// empty.
func WrapConn(c net.Conn, opts Options) net.Conn {
	if !opts.Enabled() {
		return c
	}
	return &Conn{Conn: c, opts: opts}
}

// NetConn returns the wrapped connection.
func (c *Conn) NetConn() net.Conn { return c.Conn }

// Write holds a ClientHello until its first record is complete, then sends it
// desynchronised; every other write goes straight through.
func (c *Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.done {
		c.mu.Unlock()
		return c.Conn.Write(p)
	}
	defer c.mu.Unlock()

	data := p
	if len(c.buf) > 0 {
		data = append(c.buf, p...)
		c.buf = nil
	} else if !looksLikeHello(p) {
		c.done = true
		return c.Conn.Write(p)
	}

	rl, err := recordLen(data)
	switch {
	case err == errShort || (err == nil && len(data) < rl):
		// Wait for the rest of the record (a TLS client always sends the
		// whole hello before it reads).
		// Copy: p belongs to the caller and may be reused once we return.
		c.buf = append([]byte(nil), data...)
		return len(p), nil
	case err != nil:
		c.done = true
		c.buf = nil
		if _, werr := c.Conn.Write(data); werr != nil {
			return 0, werr
		}
		return len(p), nil
	}

	c.done = true
	c.buf = nil
	if err := c.sendFirst(data[:rl]); err != nil {
		return 0, err
	}
	if len(data) > rl {
		if _, err := c.Conn.Write(data[rl:]); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// sendFirst writes the first record with the options applied.
func (c *Conn) sendFirst(rec []byte) error {
	h, err := ParseHello(rec)
	if err != nil {
		_, err = c.Conn.Write(rec)
		return err
	}
	out := rec
	recCuts := resolve(c.opts.TLSRec, h, recordHeaderLen, len(rec))
	if len(recCuts) > 0 {
		out = FragmentRecord(rec, recCuts)
	}
	tcpCuts := mapCuts(resolve(c.opts.Split, h, 0, len(rec)), recCuts)
	start := 0
	for i, end := range append(tcpCuts, len(out)) {
		if end <= start || end > len(out) {
			continue
		}
		if i > 0 && c.opts.SplitDelay > 0 {
			time.Sleep(c.opts.SplitDelay)
		}
		if _, err := c.Conn.Write(out[start:end]); err != nil {
			return err
		}
		start = end
	}
	return nil
}

// mapCuts moves offsets of the original record to the same bytes in the
// record-split output, where every record cut before them added a header. A
// TCP cut at a record cut lands before the new header, so each record starts
// its own segment.
func mapCuts(cuts, recCuts []int) []int {
	out := make([]int, 0, len(cuts))
	for _, c := range cuts {
		shift := 0
		for _, r := range recCuts {
			if r < c {
				shift += recordHeaderLen
			}
		}
		out = append(out, c+shift)
	}
	return out
}
