// Command desync-socks is a minimal SOCKS5 proxy (CONNECT only, no auth) that
// applies desync.Options to every outgoing connection. It exists to measure the
// library against a real network from any machine, the way ByeDPI's ciadpi is
// used; it is not meant for daily use.
//
//	desync-socks -listen 127.0.0.1:10802 -tlsrec 1+s
//	desync-socks -tlsrec 1+s,3+s -split 1+s
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Nemu-x/desync"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:10802", "address to listen on")
	tlsrec := flag.String("tlsrec", "", "split the ClientHello into TLS records at these positions, e.g. 1+s,3+s")
	split := flag.String("split", "", "send the ClientHello in separate TCP writes at these positions")
	delay := flag.Duration("split-delay", 0, "pause between TCP pieces")
	fake := flag.Int("fake", 0, "Windows TCP fake prefix: 0 disables, -1 means all but the last byte")
	ttl := flag.Int("ttl", 4, "TTL for a fake initial transmission")
	fakeTimeout := flag.Duration("fake-timeout", 3*time.Second, "maximum duration of a native fake operation")
	verbose := flag.Bool("v", false, "log every connection")
	flag.Parse()

	opts := desync.Options{SplitDelay: *delay}
	if *fake != 0 {
		opts.Fake = &desync.FakeOptions{TTL: *ttl, Prefix: *fake, Timeout: *fakeTimeout}
	}
	var err error
	if opts.TLSRec, err = parseList(*tlsrec); err != nil {
		log.Fatal(err)
	}
	if opts.Split, err = parseList(*split); err != nil {
		log.Fatal(err)
	}
	if err := opts.Validate(); err != nil {
		log.Fatal(err)
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("desync-socks on %s (tlsrec=%v split=%v delay=%v fake=%d ttl=%d)", ln.Addr(), opts.TLSRec, opts.Split, *delay, *fake, *ttl)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handle(c, opts, *verbose)
	}
}

func parseList(s string) ([]desync.Pos, error) {
	var out []desync.Pos
	for _, f := range strings.Split(s, ",") {
		if strings.TrimSpace(f) == "" {
			continue
		}
		p, err := desync.ParsePos(f)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func handle(c net.Conn, opts desync.Options, verbose bool) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	target, err := handshake(c)
	if err != nil {
		if verbose {
			log.Printf("socks: %v", err)
		}
		return
	}
	up, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		_, _ = c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}) // host unreachable
		if verbose {
			log.Printf("dial %s: %v", target, err)
		}
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	if verbose {
		log.Printf("connect %s", target)
	}
	w := desync.WrapConn(up, opts)
	done := make(chan struct{}, 2)
	copyStream := func(dst io.Writer, src io.Reader, halfClose net.Conn, direction string) {
		started := time.Now()
		n, err := io.Copy(dst, src)
		if verbose && err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("relay %s %s: bytes=%d elapsed=%s error=%v", target, direction, n, time.Since(started).Round(time.Millisecond), err)
		}
		closeWrite(halfClose)
		done <- struct{}{}
	}
	go copyStream(w, c, up, "client->server")
	go copyStream(c, up, c, "server->client")
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

// handshake reads a SOCKS5 greeting and CONNECT request and returns host:port.
func handshake(c net.Conn) (string, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return "", err
	}
	if hdr[0] != 5 {
		return "", errors.New("not SOCKS5")
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", err
	}
	if _, err := c.Write([]byte{5, 0}); err != nil { // no auth
		return "", err
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return "", err
	}
	if req[1] != 1 { // CONNECT only
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return "", fmt.Errorf("unsupported command %d", req[1])
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = string(b)
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	default:
		return "", fmt.Errorf("unsupported address type %d", req[3])
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(c, p); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p)))), nil
}
