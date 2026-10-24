package desync

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// captureHello returns the bytes a real Go TLS client writes first.
func captureHello(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		c := tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
		_ = c.Handshake()
		c.Close()
	}()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, err := server.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if rl, e := recordLen(buf); e == nil && len(buf) >= rl {
			return buf[:rl]
		}
		if err != nil {
			t.Fatalf("read hello: %v (got %d bytes)", err, len(buf))
		}
	}
}

func TestParseHello(t *testing.T) {
	rec := captureHello(t, "www.youtube.com")
	h, err := ParseHello(rec)
	if err != nil {
		t.Fatal(err)
	}
	if h.SNI != "www.youtube.com" || h.RecordLen != len(rec) {
		t.Fatalf("hello = %+v", h)
	}
	if got := string(rec[h.SNIOffset : h.SNIOffset+len(h.SNI)]); got != h.SNI {
		t.Fatalf("SNI offset %d points at %q", h.SNIOffset, got)
	}

	if _, err := ParseHello([]byte("GET / HTTP/1.1\r\n\r\n")); err != ErrNotClientHello {
		t.Fatalf("HTTP request: err = %v", err)
	}
	if _, err := ParseHello(rec[:len(rec)-1]); err != errShort {
		t.Fatalf("truncated: err = %v", err)
	}
	// Garbage behind a valid header must not panic or invent an SNI.
	for n := recordHeaderLen; n < len(rec); n += 7 {
		junk := append([]byte(nil), rec[:recordHeaderLen]...)
		junk[3], junk[4] = byte((n-recordHeaderLen)>>8), byte(n-recordHeaderLen)
		junk = append(junk, bytes.Repeat([]byte{0xff}, n-recordHeaderLen)...)
		if h, err := ParseHello(junk); err == nil && h.SNIOffset >= 0 {
			t.Fatalf("junk of %d bytes produced SNI %q", n, h.SNI)
		}
	}
}

func TestParsePos(t *testing.T) {
	for in, want := range map[string]Pos{"3": {3, false}, "1+s": {1, true}, "-2+s": {-2, true}, " 0 ": {0, false}} {
		got, err := ParsePos(in)
		if err != nil || got != want {
			t.Errorf("ParsePos(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "x", "1+h", "+s"} {
		if _, err := ParsePos(bad); err == nil {
			t.Errorf("ParsePos(%q) accepted", bad)
		}
	}
}

// records splits a byte stream into TLS records.
func records(t *testing.T, b []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(b) > 0 {
		if len(b) < recordHeaderLen {
			t.Fatalf("trailing %d bytes", len(b))
		}
		n := recordHeaderLen + (int(b[3])<<8 | int(b[4]))
		if n > len(b) {
			t.Fatalf("record of %d bytes, only %d left", n, len(b))
		}
		out = append(out, b[:n])
		b = b[n:]
	}
	return out
}

func TestFragmentRecordKeepsPayload(t *testing.T) {
	rec := captureHello(t, "discord.com")
	h, _ := ParseHello(rec)
	cuts := resolve([]Pos{{1, true}, {3, true}, {6, false}}, h, recordHeaderLen, len(rec))
	out := FragmentRecord(rec, cuts)
	rs := records(t, out)
	if len(rs) != len(cuts)+1 {
		t.Fatalf("%d records, want %d", len(rs), len(cuts)+1)
	}
	var payload []byte
	for _, r := range rs {
		if !bytes.Equal(r[:3], rec[:3]) {
			t.Fatalf("record header % x, want type/version % x", r[:3], rec[:3])
		}
		payload = append(payload, r[recordHeaderLen:]...)
	}
	if !bytes.Equal(payload, rec[recordHeaderLen:]) {
		t.Fatal("payload changed")
	}
	// No record boundary falls inside the 5-byte header or past the end.
	if out2 := FragmentRecord(rec, []int{0, 3, 5, len(rec), len(rec) + 9}); !bytes.Equal(out2, rec) {
		t.Fatal("out-of-range cuts changed the record")
	}
}

// recConn records every Write as one segment.
type recConn struct {
	net.Conn
	mu   sync.Mutex
	segs [][]byte
}

func (r *recConn) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.segs = append(r.segs, append([]byte(nil), p...))
	r.mu.Unlock()
	return r.Conn.Write(p)
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"www.youtube.com"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// A real TLS server must complete the handshake with a desynchronised client,
// and the bytes on the wire must be split the way the options say.
func TestWrapConnHandshake(t *testing.T) {
	cert := selfSigned(t)
	for _, tc := range []struct {
		name    string
		opts    Options
		minRecs int
		minSegs int
	}{
		{"tlsrec 1+s", Options{TLSRec: []Pos{{1, true}}}, 2, 1},
		{"tlsrec 1+s 3+s", Options{TLSRec: []Pos{{1, true}, {3, true}}}, 3, 1},
		{"split 1+s", Options{Split: []Pos{{1, true}}}, 1, 2},
		{"tlsrec+split", Options{TLSRec: []Pos{{1, true}}, Split: []Pos{{1, true}}}, 2, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			srvErr := make(chan error, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					srvErr <- err
					return
				}
				s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
				err = s.Handshake()
				if err == nil {
					_, err = s.Write([]byte("ok"))
				}
				srvErr <- err
				s.Close()
			}()

			raw, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			rc := &recConn{Conn: raw}
			c := tls.Client(WrapConn(rc, tc.opts), &tls.Config{ServerName: "www.youtube.com", InsecureSkipVerify: true})
			defer c.Close()
			buf := make([]byte, 2)
			if _, err := c.Read(buf); err != nil || string(buf) != "ok" {
				t.Fatalf("client: %q %v", buf, err)
			}
			if err := <-srvErr; err != nil {
				t.Fatalf("server: %v", err)
			}

			rc.mu.Lock()
			first := rc.segs
			rc.mu.Unlock()
			// Segments that carry the hello: everything up to the server's reply.
			var hello []byte
			segs := 0
			for _, s := range first {
				hello = append(hello, s...)
				segs++
				if rs := countRecordsUntilComplete(hello); rs > 0 {
					if rs < tc.minRecs {
						t.Fatalf("hello went out as %d records, want >= %d", rs, tc.minRecs)
					}
					break
				}
			}
			if segs < tc.minSegs {
				t.Fatalf("hello went out in %d writes, want >= %d", segs, tc.minSegs)
			}
		})
	}
}

// countRecordsUntilComplete returns how many records it takes to carry the
// whole ClientHello handshake message in b, or 0 if b does not hold it yet.
func countRecordsUntilComplete(b []byte) int {
	var payload []byte
	n := 0
	for len(b) >= recordHeaderLen {
		l := recordHeaderLen + (int(b[3])<<8 | int(b[4]))
		if l > len(b) {
			return 0
		}
		payload = append(payload, b[recordHeaderLen:l]...)
		b = b[l:]
		n++
		if len(payload) >= 4 {
			hs := 4 + (int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3]))
			if len(payload) >= hs {
				return n
			}
		}
	}
	return 0
}

// A hello written in small pieces is reassembled before it is split, and a
// connection that is not TLS is passed through unchanged.
func TestWrapConnBuffersAndPassesThrough(t *testing.T) {
	rec := captureHello(t, "www.youtube.com")
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	w := WrapConn(a, Options{TLSRec: []Pos{{1, true}}})
	got := make(chan []byte, 1)
	go func() {
		var all []byte
		tmp := make([]byte, 4096)
		_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
		for len(all) < len(rec)+recordHeaderLen {
			n, err := b.Read(tmp)
			all = append(all, tmp[:n]...)
			if err != nil {
				break
			}
		}
		got <- all
	}()
	for i := 0; i < len(rec); i += 100 {
		end := i + 100
		if end > len(rec) {
			end = len(rec)
		}
		piece := append([]byte(nil), rec[i:end]...)
		if _, err := w.Write(piece); err != nil {
			t.Fatal(err)
		}
		for j := range piece { // the caller reuses its buffer
			piece[j] = 0
		}
	}
	out := <-got
	if len(records(t, out)) != 2 {
		t.Fatalf("want the hello as 2 records")
	}

	c, d := net.Pipe()
	defer c.Close()
	defer d.Close()
	pw := WrapConn(c, Options{TLSRec: []Pos{{1, true}}})
	go func() { _, _ = pw.Write([]byte("GET / HTTP/1.1\r\n\r\n")) }()
	buf := make([]byte, 64)
	n, _ := d.Read(buf)
	if string(buf[:n]) != "GET / HTTP/1.1\r\n\r\n" {
		t.Fatalf("plain traffic changed: %q", buf[:n])
	}
}
