package desync

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

var errNoPeerAddress = errors.New("desync: socket peer has an unsupported address family")

// savedHop is the socket option that sets the TTL (IPv4) or unicast hop
// limit (IPv6) for one destination, with the value that restores it.
type savedHop struct{ level, option, restore int }

func sockaddrIP(sa syscall.Sockaddr) (net.IP, error) {
	switch a := sa.(type) {
	case *syscall.SockaddrInet4:
		return net.IP(append([]byte(nil), a.Addr[:]...)), nil
	case *syscall.SockaddrInet6:
		return net.IP(append([]byte(nil), a.Addr[:]...)), nil
	}
	return nil, errNoPeerAddress
}

// lowerHop sets the hop limit for the connected peer of raw to value and
// returns what restores it. A failed change is undone before returning.
func lowerHop(raw syscall.RawConn, value int) (savedHop, error) {
	var saved savedHop
	var opErr error
	err := raw.Control(func(fd uintptr) {
		peer, e := socketPeer(fd)
		if e != nil {
			opErr = e
			return
		}
		if saved, opErr = hopFor(fd, peer); opErr != nil {
			return
		}
		if e := setHop(fd, saved, value); e != nil {
			opErr = e
			if r := setHop(fd, saved, saved.restore); r != nil {
				opErr = fmt.Errorf("%v; restore: %w", e, r)
			}
		}
	})
	if err == nil {
		err = opErr
	}
	return saved, err
}

// restoreHop restores what lowerHop changed. A closed socket has nothing left
// to restore; its error is returned so that the caller reports it.
func restoreHop(raw syscall.RawConn, saved savedHop) error {
	var opErr error
	err := raw.Control(func(fd uintptr) { opErr = setHop(fd, saved, saved.restore) })
	if err == nil {
		err = opErr
	}
	if err != nil {
		return fmt.Errorf("desync: restore hop limit: %w", err)
	}
	return nil
}
