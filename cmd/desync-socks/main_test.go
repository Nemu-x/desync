package main

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/Nemu-x/desync"
)

// socksDial opens a CONNECT tunnel to host:port through the SOCKS5 proxy at
// proxy, sending the host as a domain name.
func socksDial(t *testing.T, proxy, host string, port int) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil || resp[1] != 0 {
		t.Fatalf("greeting: % x %v", resp, err)
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 0 {
		t.Fatalf("connect reply: % x %v", reply, err)
	}
	return c
}

func TestSocksTunnelWithTLSRec(t *testing.T) {
	socksTunnel(t, desync.Options{TLSRec: []desync.Pos{{Offset: 1, FromSNI: true}}, Split: []desync.Pos{{Offset: 1, FromSNI: true}}})
}

func TestSocksTunnelWithDisorderAndOOB(t *testing.T) {
	opts := desync.Options{Split: []desync.Pos{{Offset: 1, FromSNI: true}}, Disorder: true, OOB: &desync.OOBOptions{}}
	if err := opts.Validate(); err != nil {
		t.Skip(err)
	}
	socksTunnel(t, opts)
}

func socksTunnel(t *testing.T, opts desync.Options) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("through"))
	}))
	defer srv.Close()
	_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(c, opts, false)
		}
	}()

	conn := socksDial(t, ln.Addr().String(), "localhost", port)
	tc := tls.Client(conn, &tls.Config{ServerName: "www.youtube.com", InsecureSkipVerify: true})
	defer tc.Close()
	if _, err := tc.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(tc)
	if !contains(body, "through") {
		t.Fatalf("response %q", body)
	}
}

func contains(b []byte, s string) bool {
	return len(b) >= len(s) && string(b[len(b)-len(s):]) == s
}

func TestParseByte(t *testing.T) {
	for in, want := range map[string]byte{"a": 'a', "0xff": 0xff, "0x00": 0} {
		if got, err := parseByte(in); err != nil || got != want {
			t.Errorf("parseByte(%q) = %d, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "ab", "0x100", "0xzz"} {
		if _, err := parseByte(bad); err == nil {
			t.Errorf("parseByte(%q) accepted", bad)
		}
	}
}

func TestParseList(t *testing.T) {
	ps, err := parseList("1+s, 3+s,,7")
	if err != nil || len(ps) != 3 || ps[2] != (desync.Pos{Offset: 7}) {
		t.Fatalf("%v %v", ps, err)
	}
	if _, err := parseList("1+x"); err == nil {
		t.Fatal("bad position accepted")
	}
}

func TestSplitList(t *testing.T) {
	got := splitList(" a.example, ,*.b.example,")
	if len(got) != 2 || got[0] != "a.example" || got[1] != "*.b.example" {
		t.Fatalf("%q", got)
	}
	if splitList("") != nil {
		t.Fatal("empty list")
	}
}

// The flags' fake options validate together with split and disorder where
// the platform has the fake.
func TestFakeSplitOptions(t *testing.T) {
	opts := desync.Options{
		Split:    []desync.Pos{{Offset: 1}},
		Disorder: true,
		Fake:     &desync.FakeOptions{TTL: 4, Prefix: -1, SNI: splitList("www.example.com,*.example.org"), Randomize: true},
	}
	if err := opts.Validate(); desync.SupportsFake() && err != nil {
		t.Fatal(err)
	}
}
