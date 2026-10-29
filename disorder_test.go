package desync

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestSocketMethodValidation(t *testing.T) {
	split := []Pos{{Offset: 12}}
	for name, o := range map[string]Options{
		"disorder without split": {Disorder: true},
		"oob without split":      {OOB: &OOBOptions{}},
		"disorder records only":  {TLSRec: split, Disorder: true},
		"oob and fake, acked":    {Split: split, OOB: &OOBOptions{}, SplitWait: SplitWaitAcked, Fake: &FakeOptions{TTL: 4}},
		"disorder and acked":     {Split: split, Disorder: true, SplitWait: SplitWaitAcked},
	} {
		if err := o.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if !o.Enabled() {
			t.Errorf("%s: not enabled, so the error would never surface", name)
		}
	}
	caps := PlatformCapabilities()
	for _, o := range []Options{
		{Split: split, Disorder: true},
		{Random: &RandomOptions{Split: []RandomCut{{From: Pos{Offset: 1}, To: Pos{Offset: 40}}}}, Disorder: true},
	} {
		err := o.Validate()
		if caps.Disorder.Supported != (err == nil) || !caps.Disorder.Supported && !errors.Is(err, ErrDisorderUnsupported) {
			t.Fatalf("disorder on %s: %v, capability %+v", runtime.GOOS, err, caps.Disorder)
		}
	}
	err := Options{Split: split, OOB: &OOBOptions{}}.Validate()
	if caps.OOB != (err == nil) || !caps.OOB && !errors.Is(err, ErrOOBUnsupported) {
		t.Fatalf("oob on %s: %v", runtime.GOOS, err)
	}
	if caps.Disorder.Supported && caps.Ack.Sent {
		if err := (Options{Split: split, Disorder: true, SplitWait: SplitWaitSent}).Validate(); err != nil {
			t.Fatalf("disorder with SplitWaitSent: %v", err)
		}
	}
}

func TestSocketMethodKey(t *testing.T) {
	base := Options{Split: []Pos{{Offset: 12}}}
	if k := base.Key(); strings.Contains(k, "disorder") || strings.Contains(k, "oob") {
		t.Fatalf("key changed for options without the new methods: %s", k)
	}
	keys := map[string]bool{}
	for _, o := range []Options{
		base,
		{Split: base.Split, Disorder: true},
		{Split: base.Split, OOB: &OOBOptions{}},
		{Split: base.Split, OOB: &OOBOptions{Byte: 'b'}},
		{Split: base.Split, Disorder: true, OOB: &OOBOptions{}},
	} {
		keys[o.Key()] = true
	}
	if len(keys) != 5 {
		t.Fatalf("methods not part of the key: %v", keys)
	}
	if (Options{Split: base.Split, OOB: &OOBOptions{}}).Key() != (Options{Split: base.Split, OOB: &OOBOptions{Byte: 'a'}}).Key() {
		t.Fatal("the default urgent byte has two keys")
	}
}

func TestSocketMethodOptionsAreCopied(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	oob := &OOBOptions{Byte: 'x'}
	w := WrapConn(a, Options{Split: []Pos{{Offset: 3}}, OOB: oob}).(*Conn)
	oob.Byte = 'y'
	if w.opts.OOB.Byte != 'x' {
		t.Fatal("wrapper shares OOB options")
	}
}

// Without a socket nothing is written: no fallback to a plain split.
func TestSocketMethodRequiresSocket(t *testing.T) {
	for name, opts := range map[string]Options{
		"disorder": {Split: []Pos{{Offset: 12}}, Disorder: true},
		"oob":      {Split: []Pos{{Offset: 12}}, OOB: &OOBOptions{}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := opts.Validate(); err != nil {
				t.Skip(err)
			}
			a, b := net.Pipe()
			defer b.Close()
			got := make(chan []byte, 1)
			go func() { data, _ := io.ReadAll(b); got <- data }()
			w := WrapConn(a, opts)
			if _, err := w.Write(captureHello(t, "example.test")); !errors.Is(err, ErrSocketMethodRequiresTCP) {
				t.Fatalf("Write: %v", err)
			}
			if data := <-got; len(data) != 0 {
				t.Fatalf("%d bytes reached the peer", len(data))
			}
		})
	}
}

// tcpHop reads the hop limit that applies to the connection's peer.
func tcpHop(t testing.TB, c *net.TCPConn) int {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		peer, e := socketPeer(fd)
		if e != nil {
			opErr = e
			return
		}
		h, e := hopFor(fd, peer)
		v, opErr = h.restore, e
	}); err != nil {
		t.Fatal(err)
	}
	if opErr != nil {
		t.Fatal(opErr)
	}
	return v
}

type hopWrite struct {
	hop  int
	data []byte
	oob  bool
}

// hopConn records the socket's hop limit at every write. Failing the write
// number fail (1-based) checks restoration on errors.
type hopConn struct {
	*net.TCPConn
	t      testing.TB
	mu     sync.Mutex
	writes []hopWrite
	fail   int
}

var errInjected = errors.New("injected write failure")

func (c *hopConn) record(p []byte, oob bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, hopWrite{hop: tcpHop(c.t, c.TCPConn), data: append([]byte(nil), p...), oob: oob})
	if len(c.writes) == c.fail {
		return errInjected
	}
	return nil
}

func (c *hopConn) Write(p []byte) (int, error) {
	if err := c.record(p, false); err != nil {
		return 0, err
	}
	return c.TCPConn.Write(p)
}

// observeOOB routes the test's urgent sends through rec.
func observeOOB(t *testing.T, rec *hopConn) {
	t.Helper()
	sendOOBFunc = func(raw syscall.RawConn, p []byte) (int, error) {
		if err := rec.record(p, true); err != nil {
			return 0, err
		}
		return sendOOB(raw, p)
	}
	t.Cleanup(func() { sendOOBFunc = sendOOB })
}

func readUntil(c net.Conn, tail []byte) chan []byte {
	out := make(chan []byte, 1)
	go func() {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 0, 4096)
		chunk := make([]byte, 4096)
		for !bytes.HasSuffix(buf, tail) {
			n, err := c.Read(chunk)
			buf = append(buf, chunk[:n]...)
			if err != nil {
				break
			}
		}
		out <- buf
	}()
	return out
}

type socketMethodCase struct {
	name string
	opts Options
}

func socketMethodCases() []socketMethodCase {
	split := []Pos{{Offset: 1, FromSNI: true}}
	splits := []Pos{{Offset: 3}, {Offset: 1, FromSNI: true}, {Offset: 40, FromSNI: true}}
	rec := []Pos{{Offset: 2, FromSNI: true}}
	random := &RandomOptions{Split: []RandomCut{{From: Pos{Offset: -8, FromSNI: true}, To: Pos{Offset: 8, FromSNI: true}, Count: 2, MinPiece: 2}}, Seed: 7}
	caps := PlatformCapabilities()
	var out []socketMethodCase
	for _, m := range []struct {
		name     string
		disorder bool
		oob      *OOBOptions
	}{{"disorder", true, nil}, {"oob", false, &OOBOptions{}}, {"disoob", true, &OOBOptions{Byte: 0xff}}} {
		out = append(out,
			socketMethodCase{m.name + "/split", Options{Split: split, Disorder: m.disorder, OOB: m.oob}},
			socketMethodCase{m.name + "/tlsrec-splits", Options{TLSRec: rec, Split: splits, Disorder: m.disorder, OOB: m.oob}},
			socketMethodCase{m.name + "/random", Options{TLSRec: rec, Random: random, Disorder: m.disorder, OOB: m.oob}},
			socketMethodCase{m.name + "/delay", Options{Split: splits, SplitDelay: time.Millisecond, Disorder: m.disorder, OOB: m.oob}},
		)
		if caps.Ack.Sent {
			out = append(out, socketMethodCase{m.name + "/wait-sent", Options{TLSRec: rec, Split: splits, SplitWait: SplitWaitSent, Disorder: m.disorder, OOB: m.oob}})
		}
		if !m.disorder && caps.Ack.Acked {
			out = append(out, socketMethodCase{m.name + "/wait-acked", Options{Split: splits, SplitWait: SplitWaitAcked, OOB: m.oob}})
		}
	}
	return out
}

// wantStream is what the server must read: the record-split hello and the
// tail, with the urgent byte only when the server reads urgent data inline.
func wantStream(t *testing.T, hello, tail []byte, opts Options, inline bool) []byte {
	t.Helper()
	want := FragmentRecord(hello, resolve(opts.TLSRec, mustParse(t, hello), recordHeaderLen, len(hello)))
	if inline && opts.OOB != nil {
		if opts.Random != nil {
			t.Fatal("inline expectation supports fixed positions only")
		}
		var s helloScanner
		frame, err := s.scan(hello, (*ClientHelloOptions)(nil).limits())
		if err != nil {
			t.Fatal(err)
		}
		at := mapCuts(frame.cuts(opts.Split, false), frame.cuts(opts.TLSRec, true))[0]
		want = append(append(append([]byte(nil), want[:at]...), opts.OOB.urgentByte()), want[at:]...)
	}
	return append(want, tail...)
}

func socketMethodRoundTrip(t *testing.T, network string, opts Options, inline bool) {
	client, server := loopbackPair(t, network)
	if inline {
		raw, err := server.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var opErr error
		if err := raw.Control(func(fd uintptr) { opErr = setOOBInline(fd) }); err != nil || opErr != nil {
			t.Fatal(err, opErr)
		}
	}
	hello := captureHello(t, "example.test")
	tail := []byte("after the hello")
	before := tcpHop(t, client)
	rec := &hopConn{TCPConn: client, t: t}
	observeOOB(t, rec)
	w := WrapConn(rec, opts)
	_ = w.SetWriteDeadline(time.Now().Add(10 * time.Second))
	read := readUntil(server, tail)
	input := append(append([]byte(nil), hello...), tail...)
	if n, err := w.Write(input); err != nil || n != len(input) {
		t.Fatalf("Write: %d %v", n, err)
	}
	got := <-read
	if want := wantStream(t, hello, tail, opts, inline); !bytes.Equal(got, want) {
		t.Fatalf("stream changed: got %d bytes, want %d\ngot  %q\nwant %q", len(got), len(want), got, want)
	}
	if after := tcpHop(t, client); after != before {
		t.Fatalf("hop limit not restored: %d -> %d", before, after)
	}
	// The first piece goes out at hop limit 1 with Disorder and at the
	// original limit otherwise; only the first send carries urgent data.
	if len(rec.writes) < 2 {
		t.Fatalf("not split: %d writes", len(rec.writes))
	}
	for i, wr := range rec.writes {
		hop := before
		if i == 0 && opts.Disorder {
			hop = disorderHopLimit
		}
		if wr.hop != hop || wr.oob != (i == 0 && opts.OOB != nil) {
			t.Fatalf("write %d (%d bytes): hop %d oob %v, want hop %d", i, len(wr.data), wr.hop, wr.oob, hop)
		}
	}
	if opts.OOB != nil {
		first := rec.writes[0].data
		if first[len(first)-1] != opts.OOB.urgentByte() {
			t.Fatalf("urgent send does not end with the OOB byte: %q", first)
		}
	}
}

// Every method and combination delivers a byte-identical stream on a real
// socket and leaves the hop limit as it was.
func TestSocketMethodsNativeLoopback(t *testing.T) {
	for _, tc := range socketMethodCases() {
		if err := tc.opts.Validate(); err != nil {
			t.Logf("%s: %v", tc.name, err)
			continue
		}
		for _, network := range []string{"tcp4", "tcp6"} {
			t.Run(tc.name+"/"+network, func(t *testing.T) { socketMethodRoundTrip(t, network, tc.opts, false) })
		}
	}
}

// With SO_OOBINLINE the server reads the urgent byte at the split point, so
// it was transmitted as urgent data; without that option it is consumed.
func TestOOBByteIsUrgentData(t *testing.T) {
	opts := Options{TLSRec: []Pos{{Offset: 2, FromSNI: true}}, Split: []Pos{{Offset: 3}, {Offset: 1, FromSNI: true}}, OOB: &OOBOptions{}}
	if err := opts.Validate(); err != nil {
		t.Skip(err)
	}
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) { socketMethodRoundTrip(t, network, opts, true) })
	}
}

func TestSocketMethodsTLSHandshake(t *testing.T) {
	opts := Options{TLSRec: []Pos{{Offset: 1, FromSNI: true}}, Split: []Pos{{Offset: 1, FromSNI: true}}, Disorder: true, OOB: &OOBOptions{}}
	if err := opts.Validate(); err != nil {
		t.Skip(err)
	}
	client, server := loopbackPair(t, "tcp4")
	cert := selfSigned(t)
	serverErr := make(chan error, 1)
	go func() {
		_ = server.SetDeadline(time.Now().Add(5 * time.Second))
		s := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}})
		err := s.Handshake()
		if err == nil {
			_, err = s.Write([]byte("ok"))
		}
		serverErr <- err
	}()
	w := WrapConn(client, opts)
	_ = w.SetDeadline(time.Now().Add(5 * time.Second))
	c := tls.Client(w, &tls.Config{ServerName: "www.example.test", InsecureSkipVerify: true})
	var got [2]byte
	if _, err := io.ReadFull(c, got[:]); err != nil || string(got[:]) != "ok" {
		t.Fatalf("TLS: %q %v", got, err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func firstPieceFixture(t *testing.T, opts Options) (*Conn, *hopConn, *firstPiece, int) {
	t.Helper()
	if err := opts.Validate(); err != nil {
		t.Skip(err)
	}
	client, server := loopbackPair(t, "tcp4")
	go func() { _, _ = io.Copy(io.Discard, server) }()
	rec := &hopConn{TCPConn: client, t: t}
	w := WrapConn(rec, opts).(*Conn)
	p, err := w.prepareFirstPiece(nil)
	if err != nil {
		t.Fatal(err)
	}
	return w, rec, p, tcpHop(t, client)
}

// A failed low-hop send restores the hop limit and reports the failure.
func TestDisorderRestoresHopOnFailure(t *testing.T) {
	for _, oob := range []bool{false, true} {
		t.Run(fmt.Sprint("oob=", oob), func(t *testing.T) {
			opts := Options{Split: []Pos{{Offset: 3}}, Disorder: true}
			if oob {
				opts.OOB = &OOBOptions{}
			}
			w, rec, p, before := firstPieceFixture(t, opts)
			observeOOB(t, rec)
			rec.fail = 1
			if _, _, err := p.send(w, []byte("abc")); !errors.Is(err, errInjected) {
				t.Fatalf("send: %v", err)
			}
			if len(rec.writes) != 1 || rec.writes[0].hop != disorderHopLimit {
				t.Fatalf("writes: %+v", rec.writes)
			}
			if after := tcpHop(t, rec.TCPConn); after != before {
				t.Fatalf("hop limit leaked: %d -> %d", before, after)
			}
		})
	}
}

// The wait around the low-hop piece is bounded by the deadline, Close and
// SplitWaitTimeout, and the hop limit is restored when it ends.
func TestDisorderWaitIsBounded(t *testing.T) {
	for _, mode := range []string{"deadline", "timeout", "close"} {
		t.Run(mode, func(t *testing.T) {
			opts := Options{Split: []Pos{{Offset: 3}}, Disorder: true, SplitWaitTimeout: time.Minute}
			if mode == "timeout" {
				opts.SplitWaitTimeout = 30 * time.Millisecond
			}
			w, rec, p, before := firstPieceFixture(t, opts)
			p.obs = &stubAck{after: -1}
			want := os.ErrDeadlineExceeded
			switch mode {
			case "deadline":
				_ = w.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
			case "timeout":
				want = ErrSplitWaitTimeout
			case "close":
				want = net.ErrClosed
				time.AfterFunc(30*time.Millisecond, func() { w.Close() })
			}
			start := time.Now()
			_, _, err := p.send(w, []byte("abc"))
			if !errors.Is(err, want) {
				t.Fatalf("send: %v, want %v", err, want)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Fatalf("wait ended after %v", d)
			}
			if mode != "close" {
				if after := tcpHop(t, rec.TCPConn); after != before {
					t.Fatalf("hop limit leaked: %d -> %d", before, after)
				}
			}
		})
	}
}
