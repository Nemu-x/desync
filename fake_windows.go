//go:build windows

package desync

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const supportsFake = true
const wsaIOIncomplete = syscall.Errno(996)

var fakeSlots = make(chan struct{}, 64)

// Windows client editions process at most two TransmitFile requests at once.
// Avoid restoring TTL while an initial transmission is still queued behind
// another request. Acquisition observes the wrapper's deadline and Close.
var fakeTransmitSlots = make(chan struct{}, 2)
var kernel32Fake = syscall.NewLazyDLL("kernel32.dll")
var createEventFake = kernel32Fake.NewProc("CreateEventW")
var overlappedResultFake = syscall.NewLazyDLL("ws2_32.dll").NewProc("WSAGetOverlappedResult")

type nativeFake struct {
	file         syscall.Handle
	event        syscall.Handle
	overlap      syscall.Overlapped
	once         sync.Once
	transmitSlot bool
}

func (o *nativeFake) cleanup() {
	o.once.Do(func() {
		if o.file != syscall.InvalidHandle {
			_ = syscall.CloseHandle(o.file)
		}
		if o.event != 0 {
			_ = syscall.CloseHandle(o.event)
		}
		<-fakeSlots
		if o.transmitSlot {
			<-fakeTransmitSlots
		}
	})
	runtime.KeepAlive(o)
}

func newNativeFake(payload []byte) (*nativeFake, error) {
	select {
	case fakeSlots <- struct{}{}:
	default:
		return nil, ErrFakeBusy
	}
	o := &nativeFake{file: syscall.InvalidHandle}
	ok := false
	defer func() {
		if !ok {
			o.cleanup()
		}
	}()
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	path := filepath.Join(os.TempDir(), "desync-fake-"+hex.EncodeToString(random[:])+".tmp")
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// CREATE_NEW is atomic; DELETE_ON_CLOSE also covers process termination.
	o.file, err = syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.CREATE_NEW, 0x100|0x04000000, 0)
	if err != nil {
		return nil, os.NewSyscallError("CreateFile(fake)", err)
	}
	if err := o.rewrite(payload); err != nil {
		return nil, err
	}
	event, _, eventErr := createEventFake.Call(0, 1, 0, 0)
	if event == 0 {
		return nil, os.NewSyscallError("CreateEventW", eventErr)
	}
	o.event = syscall.Handle(event)
	// The socket belongs to Go's IOCP. Its poller must never receive our
	// foreign OVERLAPPED pointer. Windows suppresses the packet with bit 0.
	o.overlap.HEvent = o.event | 1
	ok = true
	return o, nil
}

func (o *nativeFake) rewrite(p []byte) error {
	if _, err := syscall.Seek(o.file, 0, io.SeekStart); err != nil {
		return err
	}
	for len(p) > 0 {
		var n uint32
		if err := syscall.WriteFile(o.file, p, &n, nil); err != nil {
			return os.NewSyscallError("WriteFile(fake)", err)
		}
		if n == 0 || int(n) > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func (o *nativeFake) result(socket syscall.Handle) (uint32, error) {
	var transferred, flags uint32
	r, _, err := overlappedResultFake.Call(uintptr(socket), uintptr(unsafe.Pointer(&o.overlap)),
		uintptr(unsafe.Pointer(&transferred)), 0, uintptr(unsafe.Pointer(&flags)))
	runtime.KeepAlive(o)
	if r == 0 {
		if err == syscall.Errno(0) {
			err = syscall.EINVAL
		}
		return 0, err
	}
	return transferred, nil
}

type savedTTL struct{ level, option, value int }

func restoreFakeTTL(socket syscall.Handle, saved []savedTTL) error {
	var first error
	for _, v := range saved {
		if err := syscall.SetsockoptInt(socket, v.level, v.option, v.value); err != nil && first == nil {
			first = os.NewSyscallError("restore socket TTL", err)
		}
	}
	return first
}

func setFakeTTL(socket syscall.Handle, ttl int) ([]savedTTL, error) {
	peer, err := syscall.Getpeername(socket)
	if err != nil {
		return nil, os.NewSyscallError("read fake TCP peer", err)
	}
	option := savedTTL{level: syscall.IPPROTO_IP, option: syscall.IP_TTL}
	switch addr := peer.(type) {
	case *syscall.SockaddrInet4:
	case *syscall.SockaddrInet6:
		if net.IP(addr.Addr[:]).To4() == nil {
			option.level, option.option = syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS
		}
	default:
		return nil, fmt.Errorf("desync: fake TCP peer has unsupported address family")
	}
	// Reading IP_TTL can succeed on an IPv6-only Windows socket even though
	// setting it fails. A connected TCP socket has one peer family: change
	// only its applicable option, including IPv4-mapped dual-stack peers.
	old, err := getsockoptInt(socket, option.level, option.option)
	if err != nil {
		return nil, os.NewSyscallError("read fake TTL", err)
	}
	option.value = old
	saved := []savedTTL{option}
	if err := syscall.SetsockoptInt(socket, option.level, option.option, ttl); err != nil {
		if restoreErr := restoreFakeTTL(socket, saved); restoreErr != nil {
			return nil, fmt.Errorf("set TTL: %v; restore: %w", err, restoreErr)
		}
		return nil, os.NewSyscallError("set fake TTL", err)
	}
	return saved, nil
}

// reap retains all kernel-referenced memory until cancellation completes.
// It never accesses the socket, whose handle may have been closed/reused.
func (o *nativeFake) reap() {
	for {
		state, err := syscall.WaitForSingleObject(o.event, syscall.INFINITE)
		if err == nil && state == syscall.WAIT_OBJECT_0 {
			o.cleanup()
			return
		}
		time.Sleep(time.Second)
	}
}

func (c *Conn) sendFake(real, payload, tail []byte) error {
	start := time.Now()
	if err := c.fakeAbort(start); err != nil {
		return err
	}
	socketConn, ok := c.Conn.(syscall.Conn)
	if !ok {
		return ErrFakeRequiresTCP
	}
	raw, err := socketConn.SyscallConn()
	if err != nil {
		return err
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
acquire:
	for {
		if err := c.fakeAbort(start); err != nil {
			return err
		}
		select {
		case fakeTransmitSlots <- struct{}{}:
			break acquire
		case <-c.closed:
			return net.ErrClosed
		case <-ticker.C:
		}
	}
	op, err := newNativeFake(payload)
	if err != nil {
		<-fakeTransmitSlots
		return err
	}
	op.transmitSlot = true
	detached := false
	defer func() {
		if !detached {
			op.cleanup()
		}
	}()
	var nativeErr error
	submitted := false
	err = raw.Control(func(fd uintptr) {
		socket := syscall.Handle(fd)
		if nativeErr = c.fakeAbort(start); nativeErr != nil {
			return
		}
		nativeErr = func() (callErr error) {
			saved, ttlErr := setFakeTTL(socket, c.opts.Fake.TTL)
			if ttlErr != nil {
				return ttlErr
			}
			defer func() {
				if restoreErr := restoreFakeTTL(socket, saved); restoreErr != nil {
					if callErr != nil {
						callErr = fmt.Errorf("%v; %w", callErr, restoreErr)
					} else {
						callErr = restoreErr
					}
				}
			}()
			if _, seekErr := syscall.Seek(op.file, 0, io.SeekStart); seekErr != nil {
				return seekErr
			}
			callErr = syscall.TransmitFile(socket, op.file, uint32(len(real)), uint32(len(real)),
				&op.overlap, nil, syscall.TF_USE_KERNEL_APC|syscall.TF_WRITE_BEHIND)
			if callErr != nil && !errors.Is(callErr, syscall.ERROR_IO_PENDING) {
				return os.NewSyscallError("TransmitFile(fake)", callErr)
			}
			submitted = true
			// Replace the file cache with original bytes before retransmission.
			// This follows the Windows mechanism documented by ByeDPI v0.17.3.
			return op.rewrite(real)
		}()
	})
	if err != nil {
		return err
	}
	if !submitted {
		return nativeErr
	}
	// ByeDPI sends this normal-TTL tail immediately after restoring the file
	// cache and TTL. Waiting for the prefix first can block until timeout:
	// the initial low-TTL data may require TCP retransmission and tail ACKs.
	if nativeErr == nil {
		if tailErr := writeAll(c.Conn, tail); tailErr != nil {
			nativeErr = fmt.Errorf("write original tail: %w", tailErr)
		}
	}
	err = raw.Control(func(fd uintptr) {
		socket := syscall.Handle(fd)
		for nativeErr == nil {
			n, resultErr := op.result(socket)
			if !errors.Is(resultErr, wsaIOIncomplete) {
				if resultErr != nil {
					nativeErr = os.NewSyscallError("WSAGetOverlappedResult(fake)", resultErr)
				}
				if nativeErr == nil && n != uint32(len(real)) {
					nativeErr = io.ErrShortWrite
				}
				return
			}
			if nativeErr = c.fakeAbort(start); nativeErr != nil {
				break
			}
			if _, waitErr := syscall.WaitForSingleObject(op.event, 10); waitErr != nil {
				nativeErr = waitErr
				break
			}
		}
		// Returning the error makes Conn close the socket, interrupting other
		// reads/writes too. A cancelled OVERLAPPED may outlive this callback.
		_ = syscall.CancelIoEx(socket, &op.overlap)
		if _, resultErr := op.result(socket); errors.Is(resultErr, wsaIOIncomplete) {
			detached = true
			go op.reap()
		}
	})
	runtime.KeepAlive(op)
	if err != nil {
		// Close can make the second Control fail while TransmitFile is still
		// pending. Keep its file/event/OVERLAPPED alive until the close cancels
		// it; the reaper must not touch a potentially reused socket handle.
		if !detached {
			detached = true
			go op.reap()
		}
		if nativeErr == nil {
			nativeErr = err
		}
	}
	if nativeErr != nil {
		return fmt.Errorf("desync: TCP fake: %w", nativeErr)
	}
	return nil
}
