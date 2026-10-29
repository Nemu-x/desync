//go:build linux

package desync

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const supportsFake = true

// fakeUnsupportedReason is unused on Linux, where the fake is implemented.
const fakeUnsupportedReason = ""

// fakeSlots bounds the pages and pipes held by concurrent fake operations.
var fakeSlots = make(chan struct{}, 64)

const (
	spliceFMove     = 0x1 // linux/splice.h SPLICE_F_MOVE
	spliceFNonblock = 0x2 // SPLICE_F_NONBLOCK
	spliceFGift     = 0x8 // SPLICE_F_GIFT
	// spliceChunk stays within a default pipe (16 buffers of at least 4 KiB).
	spliceChunk = 64 << 10
)

// spliceFake owns one shared anonymous mapping holding the prefix and a pipe.
//
// The mechanism follows ByeDPI v0.17.3 (desync.c send_fake, MIT; see
// third_party/BYEDPI-LICENSE): vmsplice puts references to the mapping's
// pages into the pipe, and splice moves those references into the socket's
// send queue without copying. The queued segment therefore reads the page
// whenever it is transmitted. The page holds the fake bytes during the first,
// low-hop transmission and the original bytes before the hop limit is
// restored, so a retransmission carries the original. Unlike ByeDPI the
// mapping is MAP_SHARED: a fork cannot make it copy-on-write, which would
// leave the kernel's reference on a page still holding the fake bytes.
type spliceFake struct {
	page      []byte
	pipe      [2]int
	restored  bool
	unmapped  bool
	pipesOpen bool
}

func newSpliceFake(payload []byte) (*spliceFake, error) {
	size := len(payload)
	pageSize := os.Getpagesize()
	size = (size + pageSize - 1) / pageSize * pageSize
	page, err := syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED|syscall.MAP_ANON)
	if err != nil {
		return nil, os.NewSyscallError("mmap(fake)", err)
	}
	o := &spliceFake{page: page}
	copy(o.page, payload)
	var p [2]int
	if err := syscall.Pipe2(p[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK); err != nil {
		o.restored = true // nothing references the page yet
		o.release()
		return nil, os.NewSyscallError("pipe2(fake)", err)
	}
	o.pipe, o.pipesOpen = p, true
	return o, nil
}

// restore writes the original bytes over the page the kernel may reference.
func (o *spliceFake) restore(real []byte) {
	copy(o.page, real)
	o.restored = true
}

// release closes the pipe (dropping references it still holds) and unmaps
// the page. The kernel keeps its own page references alive; their content is
// the original bytes written by restore.
func (o *spliceFake) release() {
	if o.pipesOpen {
		_ = syscall.Close(o.pipe[0])
		_ = syscall.Close(o.pipe[1])
		o.pipesOpen = false
	}
	if !o.unmapped && o.restored {
		_ = syscall.Munmap(o.page)
		o.unmapped = true
	}
}

func vmsplice(fd int, p []byte, flags int) (int, error) {
	iov := syscall.Iovec{Base: &p[0]}
	iov.SetLen(len(p))
	n, _, errno := syscall.Syscall6(syscall.SYS_VMSPLICE, uintptr(fd), uintptr(unsafe.Pointer(&iov)), 1, uintptr(flags), 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

// step moves up to one chunk from the page through the pipe into the socket.
// It returns the bytes that reached the socket and whether it must wait for
// socket space.
func (o *spliceFake) step(fd uintptr, sent, inPipe, total int) (moved, piped int, again bool, err error) {
	if inPipe == 0 {
		end := sent + spliceChunk
		if end > total {
			end = total
		}
		n, err := vmsplice(o.pipe[1], o.page[sent:end], spliceFGift|spliceFNonblock)
		if err != nil {
			return 0, 0, false, os.NewSyscallError("vmsplice(fake)", err)
		}
		if n <= 0 {
			return 0, 0, false, os.NewSyscallError("vmsplice(fake)", syscall.EIO)
		}
		inPipe, piped = n, n
	}
	n, err := syscall.Splice(o.pipe[0], nil, int(fd), nil, inPipe, spliceFMove|spliceFNonblock)
	if err == syscall.EAGAIN || err == syscall.EINTR {
		return 0, piped, true, nil
	}
	if err != nil {
		return 0, piped, false, os.NewSyscallError("splice(fake)", err)
	}
	if n <= 0 {
		return 0, piped, false, os.NewSyscallError("splice(fake)", syscall.EIO)
	}
	return int(n), piped, false, nil
}

func (c *Conn) sendFake(real, payload, tail []byte) error {
	start := time.Now()
	if err := c.fakeAbort(start); err != nil {
		return err
	}
	raw, err := socketOf(c.Conn)
	if err != nil {
		return ErrFakeRequiresTCP
	}
	obs, err := newAckObserver(raw)
	if err != nil {
		return fmt.Errorf("desync: TCP fake: %w", err)
	}
	select {
	case fakeSlots <- struct{}{}:
	default:
		return ErrFakeBusy
	}
	defer func() { <-fakeSlots }()
	op, err := newSpliceFake(payload)
	if err != nil {
		return err
	}
	if err := c.spliceFake(raw, obs, op, real, start); err != nil {
		return fmt.Errorf("desync: TCP fake: %w", err)
	}
	// The original prefix is in place and the hop limit restored: the tail
	// and every retransmission go out normally.
	if err := writeAll(c.Conn, tail); err != nil {
		return fmt.Errorf("desync: TCP fake: write original tail: %w", err)
	}
	return nil
}

// spliceFake transmits the fake prefix with the low hop limit. Whatever
// happens, the page is rewritten with the original bytes, then the hop limit
// is restored, then the resources are released.
func (c *Conn) spliceFake(raw syscall.RawConn, obs ackObserver, op *spliceFake, real []byte, start time.Time) (err error) {
	defer func() {
		op.restore(real)
		op.release()
	}()
	saved, err := lowerHop(raw, c.opts.Fake.TTL)
	if err != nil {
		return err
	}
	defer func() {
		// The page must hold the original bytes before a normal hop limit
		// lets a retransmission reach the server.
		op.restore(real)
		if restoreErr := restoreHop(raw, saved); restoreErr != nil {
			err = errors.Join(err, restoreErr)
		}
	}()
	timeout := c.opts.Fake.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	remaining := func() time.Duration { return timeout - time.Since(start) }
	sent, inPipe := 0, 0
	err = c.poll(remaining(), os.ErrDeadlineExceeded, "splice", func() (bool, error) {
		var opErr error
		controlErr := raw.Control(func(fd uintptr) {
			for sent < len(real) {
				moved, piped, again, e := op.step(fd, sent, inPipe, len(real))
				inPipe += piped - moved
				sent += moved
				if e != nil || again {
					opErr = e
					return
				}
			}
		})
		if controlErr != nil {
			return false, controlErr
		}
		return sent == len(real), opErr
	})
	if err != nil {
		return err
	}
	// Keep the fake bytes and low hop limit until the kernel transmitted the
	// whole prefix once (SIOCOUTQNSD is zero).
	return c.poll(remaining(), os.ErrDeadlineExceeded, "fake transmission", func() (bool, error) {
		return obs.reached(SplitWaitSent, int64(len(real)))
	})
}
