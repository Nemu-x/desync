//go:build !linux && !darwin && !windows

package desync

import (
	"errors"
	"net"
)

var errHopUnsupported = errors.New("desync: changing the hop limit is not implemented on this platform")

func hopFor(uintptr, net.IP) (savedHop, error) { return savedHop{}, errHopUnsupported }
func setHop(uintptr, savedHop, int) error      { return errHopUnsupported }
func socketPeer(uintptr) (net.IP, error)       { return nil, errHopUnsupported }

var platformDisorder = DisorderCapability{}
