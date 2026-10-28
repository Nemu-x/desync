//go:build windows

package desync

import (
	"net"
	"syscall"
	"testing"
	"time"
)

func TestNativeFakeTTLSelectsPeerFamilyAndRestores(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			level, option := syscall.IPPROTO_IP, syscall.IP_TTL
			if network == "tcp6" {
				address = "[::1]:0"
				level, option = syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS
			}
			ln, err := net.Listen(network, address)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			c, err := net.DialTimeout(network, ln.Addr().String(), 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			peer, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			raw, _ := c.(*net.TCPConn).SyscallConn()
			var normalTTL int
			if err = raw.Control(func(fd uintptr) {
				socket := syscall.Handle(fd)
				before, err := getsockoptInt(socket, level, option)
				if err != nil {
					t.Error(err)
					return
				}
				normalTTL = before
				saved, err := setFakeTTL(socket, 4)
				if err != nil {
					t.Error(err)
					return
				}
				defer func() {
					if err := restoreFakeTTL(socket, saved); err != nil {
						t.Error(err)
					}
				}()
				if len(saved) != 1 || saved[0].level != level || saved[0].option != option || saved[0].value != before {
					t.Errorf("wrong snapshot: %+v", saved)
				}
				during, err := getsockoptInt(socket, level, option)
				if err != nil || during != 4 {
					t.Errorf("fake TTL=%d error=%v", during, err)
				}
			}); err != nil {
				t.Fatal(err)
			}
			if err = raw.Control(func(fd uintptr) {
				after, err := getsockoptInt(syscall.Handle(fd), level, option)
				if err != nil || after != normalTTL {
					t.Errorf("restored TTL=%d want=%d error=%v", after, normalTTL, err)
				}
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
