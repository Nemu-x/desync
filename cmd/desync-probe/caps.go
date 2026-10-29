package main

import (
	"net"
	"time"

	"github.com/Nemu-x/desync"
)

// platformCapabilities returns what desync implements here. Methods that
// depend on the socket (desync.Capabilities.Conditional, on Android) are
// decided on a loopback connection: the restriction belongs to this
// process's SELinux domain and the kernel, which every socket shares. If
// the probe fails they stay unavailable.
func platformCapabilities() desync.Capabilities {
	caps := desync.PlatformCapabilities()
	if len(caps.Conditional) == 0 {
		return caps
	}
	if probed, err := probeLoopback(); err == nil {
		return probed
	}
	return caps
}

func probeLoopback() (desync.Capabilities, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return desync.Capabilities{}, err
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		return desync.Capabilities{}, err
	}
	defer c.Close()
	if peer := <-accepted; peer != nil {
		defer peer.Close()
	}
	return desync.ProbeCapabilities(c)
}
