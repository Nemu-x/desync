package desync

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// fragmentedTLSWriter is a test-only input source: it reframes the Go client's
// complete hello, then sends that input through the wrapper in small writes.
type fragmentedTLSWriter struct {
	net.Conn
	chunk   int
	done    bool
	prepare func([]byte) error
}

func (c *fragmentedTLSWriter) Write(p []byte) (int, error) {
	if c.done {
		return c.Conn.Write(p)
	}
	h, err := ParseHello(p)
	if err != nil {
		return 0, err
	}
	wire := reframeInput(p[:h.RecordLen], 1, 2, 3, h.SNIOffset-5+1)
	wire = append(wire, p[h.RecordLen:]...)
	if c.prepare != nil {
		if err := c.prepare(wire); err != nil {
			return 0, err
		}
	}
	c.done = true
	for len(wire) > 0 {
		n := c.chunk
		if n > len(wire) {
			n = len(wire)
		}
		written, err := c.Conn.Write(wire[:n])
		if err != nil {
			return 0, err
		}
		if written != n {
			return 0, io.ErrShortWrite
		}
		wire = wire[n:]
	}
	return len(p), nil
}

func framedTLSRoundTrip(t *testing.T, network string, chunk int, fake bool, versions ...uint16) {
	t.Helper()
	var maxVersion uint16
	if len(versions) > 0 {
		maxVersion = versions[0]
	}
	address := "127.0.0.1:0"
	if network == "tcp6" {
		address = "[::1]:0"
	}
	ln, err := net.Listen(network, address)
	if err != nil {
		if network == "tcp6" {
			t.Skipf("IPv6 unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer ln.Close()
	cert := selfSigned(t)
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	server := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			server <- err
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(5 * time.Second))
		conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: maxVersion})
		if err = conn.Handshake(); err == nil {
			_, err = conn.Write([]byte("ok"))
		}
		server <- err
	}()
	raw, err := net.DialTimeout(network, ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{TLSRec: []Pos{{Offset: 1, FromSNI: true}}}
	if fake {
		opts.Fake = &FakeOptions{TTL: 64, Prefix: -1, Timeout: time.Second}
	} else {
		opts.Split = []Pos{{Offset: 3, FromSNI: true}}
	}
	w := WrapConn(raw, opts).(*Conn)
	defer w.Close()
	w.SetDeadline(time.Now().Add(5 * time.Second))
	input := &fragmentedTLSWriter{Conn: w, chunk: chunk}
	if fake {
		input.prepare = func(wire []byte) error {
			// Native mechanism test only: use actual bytes as the alternate
			// payload, allowing the loopback TLS server to verify the handshake.
			var scanner helloScanner
			frame, err := scanner.scan(wire, opts.ClientHello.limits())
			if err != nil {
				return err
			}
			w.opts.Fake.Payload = fragmentHello(wire[:frame.wireLen], frame, frame.cuts(opts.TLSRec, true))
			return nil
		}
	}
	client := tls.Client(input, &tls.Config{ServerName: "www.youtube.com", RootCAs: roots, MaxVersion: maxVersion})
	defer client.Close()
	var reply [2]byte
	if _, err = io.ReadFull(client, reply[:]); err != nil || string(reply[:]) != "ok" {
		t.Fatalf("verified TLS: %q %v", reply, err)
	}
	select {
	case err := <-server:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server handshake did not finish")
	}
}

func TestFramedVerifiedTLSOverIPv4AndIPv6(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, chunk := range []int{1, 7, 65536} {
			t.Run(fmt.Sprintf("%s/chunk%d", network, chunk), func(t *testing.T) { framedTLSRoundTrip(t, network, chunk, false) })
		}
	}
}

func TestNativeFakeFramedVerifiedTLS(t *testing.T) {
	if !SupportsFake() {
		t.Skip("native fake is unavailable on this platform")
	}
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) { framedTLSRoundTrip(t, network, 7, true) })
	}
}

func TestFramedVerifiedTLS12(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) { framedTLSRoundTrip(t, network, 7, false, tls.VersionTLS12) })
		if SupportsFake() {
			t.Run(network+"/native-fake", func(t *testing.T) { framedTLSRoundTrip(t, network, 7, true, tls.VersionTLS12) })
		}
	}
}
