package desync

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// segmentSink records every Write call as one segment and accepts it whole.
type segmentSink struct {
	net.Conn
	mu   sync.Mutex
	segs [][]byte
}

func (s *segmentSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	s.segs = append(s.segs, append([]byte(nil), p...))
	s.mu.Unlock()
	return len(p), nil
}

func (s *segmentSink) data() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Join(s.segs, nil)
}

func newSegmentSink(t testing.TB) *segmentSink {
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return &segmentSink{Conn: a}
}

// randomRun writes input in chunks through a wrapper and returns the sink.
func randomRun(t testing.TB, opts Options, input []byte, chunk int) *segmentSink {
	t.Helper()
	sink := newSegmentSink(t)
	w := WrapConn(sink, opts)
	defer w.Close()
	for at := 0; at < len(input); {
		end := at + chunk
		if end > len(input) {
			end = len(input)
		}
		if n, err := w.Write(input[at:end]); n != end-at || err != nil {
			t.Fatalf("write: %d %v", n, err)
		}
		at = end
	}
	return sink
}

// checkRandomOutput validates framing of the transformed hello independently
// of the implementation and returns its logical record boundaries. Every output
// record must be non-empty, within the TLS limit and carry the type/version of
// the input record its first byte came from; logical bytes and the tail must
// be unchanged.
func checkRandomOutput(t *testing.T, wire, out []byte) []int {
	t.Helper()
	var scanner helloScanner
	frame, err := scanner.scan(wire, (*ClientHelloOptions)(nil).limits())
	if err != nil {
		t.Fatalf("input is not a complete hello: %v", err)
	}
	var headerAt []int // logical offset -> index of input record
	for i := 0; i < frame.records.count; i++ {
		r := frame.records.at(i)
		for j := r.start + recordHeaderLen; j < r.end; j++ {
			headerAt = append(headerAt, r.start)
		}
	}
	var payload, bounds []int
	end, logical := 0, 0
	for logical < frame.size {
		if len(out)-end < recordHeaderLen {
			t.Fatal("incomplete output header")
		}
		n := int(out[end+3])<<8 | int(out[end+4])
		if n == 0 || n > maxRecordPayload || n > len(out)-end-recordHeaderLen {
			t.Fatalf("invalid output record length %d", n)
		}
		src := headerAt[logical]
		if !bytes.Equal(out[end:end+3], wire[src:src+3]) {
			t.Fatalf("record type/version % x, want % x", out[end:end+3], wire[src:src+3])
		}
		if logical > 0 {
			bounds = append(bounds, logical)
		}
		payload = append(payload, n)
		logical += n
		end += recordHeaderLen + n
	}
	if !bytes.Equal(framingPayload(t, out[:end]), framingPayload(t, wire[:frame.wireLen])) {
		t.Fatal("logical handshake bytes changed")
	}
	if !bytes.Equal(out[end:], wire[frame.wireLen:]) {
		t.Fatal("trailing bytes changed")
	}
	return bounds
}

func checkSegments(t testing.TB, segs [][]byte) {
	t.Helper()
	for i, s := range segs {
		if len(s) == 0 {
			t.Fatalf("empty write %d", i)
		}
	}
}

func TestRandomRecordCutsStayInRangeWithMinPiece(t *testing.T) {
	rec := framingHello("random.example", 300)
	h, _ := ParseHello(rec)
	sni := h.SNIOffset - recordHeaderLen
	cut := RandomCut{From: Pos{-5, true}, To: Pos{20, true}, Count: 3, MinPiece: 4}
	seen := map[int]bool{}
	for seed := uint64(1); seed <= 500; seed++ {
		opts := Options{Random: &RandomOptions{TLSRec: []RandomCut{cut}, Seed: seed}}
		sink := randomRun(t, opts, rec, len(rec))
		checkSegments(t, sink.segs)
		bounds := checkRandomOutput(t, rec, sink.data())
		if len(bounds) != 3 {
			t.Fatalf("seed=%d: %d cuts, want 3", seed, len(bounds))
		}
		for i, b := range bounds {
			if b < sni-5 || b > sni+20 {
				t.Fatalf("seed=%d: cut %d outside range", seed, b)
			}
			if i > 0 && b-bounds[i-1] < 4 {
				t.Fatalf("seed=%d: pieces %v below minimum", seed, bounds)
			}
			seen[b-sni] = true
		}
	}
	// 500 seeds draw every allowed position of the 26-byte range.
	for off := -5; off <= 20; off++ {
		if !seen[off] {
			t.Fatalf("position %d+s never drawn", off)
		}
	}
}

func TestRandomAbsoluteRangeAcrossInputRecords(t *testing.T) {
	rec := framingHello("random.example", 300)
	wire := reframeInput(rec, 10, 60)
	wire[2] = 1 // the first input record keeps its legacy version
	wire = append(wire, []byte("trailing application bytes")...)
	cut := RandomCut{From: Pos{Offset: 0}, To: Pos{Offset: 200}, Count: 12, MinPiece: 2}
	for seed := uint64(1); seed <= 200; seed++ {
		opts := Options{Random: &RandomOptions{TLSRec: []RandomCut{cut}, Seed: seed}}
		for _, chunk := range []int{1, 13, len(wire)} {
			sink := randomRun(t, opts, wire, chunk)
			checkSegments(t, sink.segs)
			bounds := checkRandomOutput(t, wire, sink.data())
			// Two existing boundaries plus at most 12 drawn cuts, all in range.
			if len(bounds) < 2 || len(bounds) > 14 {
				t.Fatalf("seed=%d: %d boundaries", seed, len(bounds))
			}
			for _, b := range bounds {
				if b > 200-3*recordHeaderLen {
					t.Fatalf("seed=%d: cut %d past range end", seed, b)
				}
			}
		}
	}
}

func TestRandomSeedReproducesAcrossConnectionsAndChunking(t *testing.T) {
	rec := framingHello("random.example", 300)
	wire := append(reframeInput(rec, 77), framingRecord([]byte{1, 2, 3})...)
	policy := &RandomOptions{
		TLSRec: []RandomCut{{From: Pos{-10, true}, To: Pos{14, true}, Count: 3, MinPiece: 2}},
		Split:  []RandomCut{{From: Pos{Offset: 1}, To: Pos{Offset: 300}, Count: 4, MinPiece: 16}},
		Seed:   0x5eed,
	}
	opts := Options{TLSRec: []Pos{{Offset: 1, FromSNI: true}}, Random: policy}
	want := randomRun(t, opts, wire, len(wire))
	checkSegments(t, want.segs)
	checkRandomOutput(t, wire, want.data())
	for _, chunk := range []int{1, 5, 64, len(wire)} {
		// The hello writes match exactly; later input passes through per chunk.
		got := randomRun(t, opts, wire, chunk)
		hello := len(want.segs) - 1
		if len(got.segs) < hello || !bytes.Equal(got.data(), want.data()) {
			t.Fatalf("chunk=%d: output differs for the same seed", chunk)
		}
		for i := 0; i < hello; i++ {
			if !bytes.Equal(got.segs[i], want.segs[i]) {
				t.Fatalf("chunk=%d: write %d differs for the same seed", chunk, i)
			}
		}
	}
	// The hello plus one tail write: four random write cuts give five pieces.
	if len(want.segs) != 6 {
		t.Fatalf("%d writes, want 6", len(want.segs))
	}
	distinct := map[string]bool{}
	for seed := uint64(1); seed <= 32; seed++ {
		p := *policy
		p.Seed = seed
		distinct[string(bytes.Join(randomRun(t, Options{Random: &p}, wire, len(wire)).segs, []byte{0}))] = true
	}
	if len(distinct) < 16 {
		t.Fatalf("only %d distinct outputs for 32 seeds", len(distinct))
	}
}

// The draw sequence is a compatibility promise of keyVersion. If this golden
// output changes, bump keyVersion so cached seeded strategy IDs change too.
func TestRandomSeedGolden(t *testing.T) {
	rec := framingHello("random.example", 0)
	opts := Options{Random: &RandomOptions{
		TLSRec: []RandomCut{{From: Pos{Offset: 0}, To: Pos{Offset: 60}, Count: 3}},
		Split:  []RandomCut{{From: Pos{0, true}, To: Pos{13, true}, Count: 2}},
		Seed:   42,
	}}
	sink := randomRun(t, opts, rec, len(rec))
	bounds := checkRandomOutput(t, rec, sink.data())
	var sizes []int
	for _, seg := range sink.segs {
		sizes = append(sizes, len(seg))
	}
	if got := fmt.Sprint(bounds, sizes); got != goldenSeed42 {
		t.Fatalf("seed 42 draws changed: %s (want %s); bump keyVersion", got, goldenSeed42)
	}
}

const goldenSeed42 = "[14 20 51] [79 3 8]"

func TestRandomUnseededVariesPerConnection(t *testing.T) {
	rec := framingHello("random.example", 300)
	opts := Options{Random: &RandomOptions{
		TLSRec: []RandomCut{{From: Pos{Offset: 6}, To: Pos{Offset: 300}, Count: 2}},
		Split:  []RandomCut{{From: Pos{0, true}, To: Pos{13, true}}},
	}}
	distinct := map[string]bool{}
	for i := 0; i < 64; i++ {
		sink := randomRun(t, opts, rec, len(rec))
		checkSegments(t, sink.segs)
		if len(sink.segs) != 2 {
			t.Fatalf("%d writes, want 2", len(sink.segs))
		}
		if b := checkRandomOutput(t, rec, sink.data()); len(b) != 2 {
			t.Fatalf("%d record cuts, want 2", len(b))
		}
		distinct[string(bytes.Join(sink.segs, []byte{0}))] = true
	}
	if len(distinct) < 32 {
		t.Fatalf("unseeded policy produced only %d distinct outputs", len(distinct))
	}
}

func TestRandomIgnoredRangesKeepDeterministicOutput(t *testing.T) {
	rec := framingHello("random.example", 300)
	noSNI := framingHello("random.example", 0)
	noSNI[6], noSNI[7], noSNI[8] = 0, 0, 41 // minimal TLS 1.2 body, no extensions
	noSNI = noSNI[:5+45]
	noSNI[3], noSNI[4] = 0, 45
	if h, err := ParseHello(noSNI); err != nil || h.SNIOffset != -1 {
		t.Fatalf("fixture: %+v %v", h, err)
	}
	det := Options{TLSRec: []Pos{{Offset: 12}, {Offset: 1, FromSNI: true}}, Split: []Pos{{Offset: 30}}}
	ignored := &RandomOptions{
		// Beyond the hello, before it, without SNI, or too small for MinPiece.
		TLSRec: []RandomCut{{From: Pos{Offset: 5000}, To: Pos{Offset: 6000}}, {From: Pos{Offset: -9}, To: Pos{Offset: 0}}},
		Split:  []RandomCut{{From: Pos{0, true}, To: Pos{5, true}, MinPiece: 1 << 15}},
		Seed:   7,
	}
	for _, input := range [][]byte{rec, noSNI} {
		want := randomRun(t, det, input, len(input))
		withRandom := det
		withRandom.Random = ignored
		got := randomRun(t, withRandom, input, len(input))
		if len(got.segs) != len(want.segs) || !bytes.Equal(got.data(), want.data()) {
			t.Fatal("ignored random ranges changed deterministic output")
		}
	}
	sniOnly := Options{Random: &RandomOptions{TLSRec: []RandomCut{{From: Pos{0, true}, To: Pos{3, true}}}}}
	if got := randomRun(t, sniOnly, noSNI, len(noSNI)); !bytes.Equal(got.data(), noSNI) {
		t.Fatal("SNI-relative random range changed a hello without SNI")
	}
	raw := newSegmentSink(t)
	if WrapConn(raw, Options{Random: &RandomOptions{Seed: 3}}) != net.Conn(raw) {
		t.Fatal("a seed without ranges enabled the wrapper")
	}
}

func TestRandomPartialWriteCounts(t *testing.T) {
	rec := framingHello("random.example", 300)
	opts := Options{Random: &RandomOptions{
		TLSRec: []RandomCut{{From: Pos{-20, true}, To: Pos{40, true}, Count: 4, MinPiece: 3}},
		Seed:   99,
	}}
	ok := randomRun(t, opts, rec, len(rec))
	out := ok.data()
	rs := records(t, out)
	if len(rs) != 5 {
		t.Fatalf("%d records", len(rs))
	}
	for _, buffered := range []int{0, 9} {
		for fail := 0; fail < len(out); fail++ {
			// Generated headers are those of every output record but the first.
			want, at := fail, 0
			for i, r := range rs {
				if i > 0 {
					overlap := fail - at
					if overlap > recordHeaderLen {
						overlap = recordHeaderLen
					}
					if overlap > 0 {
						want -= overlap
					}
				}
				at += len(r)
			}
			raw := lifecycleStream(t)
			raw.failCall, raw.failAfter = 1, fail
			w := WrapConn(raw, opts)
			if buffered > 0 {
				if _, err := w.Write(rec[:buffered]); err != nil {
					t.Fatal(err)
				}
			}
			n, err := w.Write(rec[buffered:])
			want -= buffered
			if want < 0 {
				want = 0
			}
			if n != want || !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("buffered=%d fail=%d: n=%d want=%d err=%v", buffered, fail, n, want, err)
			}
			w.Close()
		}
	}
}

func TestRandomSplitDelayIsInterruptible(t *testing.T) {
	rec := framingHello("random.example", 0)
	raw := lifecycleStream(t)
	opts := Options{
		Random:     &RandomOptions{Split: []RandomCut{{From: Pos{0, true}, To: Pos{10, true}}}, Seed: 1},
		SplitDelay: time.Hour,
	}
	w := WrapConn(raw, opts)
	defer w.Close()
	done := make(chan error, 1)
	go func() { _, err := w.Write(rec); done <- err }()
	time.Sleep(20 * time.Millisecond)
	if err := w.SetWriteDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("delay error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("random split delay ignored a deadline change")
	}
}

func TestRandomValidation(t *testing.T) {
	ok := []RandomOptions{
		{TLSRec: []RandomCut{{From: Pos{-3, true}, To: Pos{3, true}, Count: MaxRandomCount, MinPiece: 1}}},
		{Split: []RandomCut{{From: Pos{Offset: 1}, To: Pos{Offset: 1}}}, Seed: 1},
		{TLSRec: make([]RandomCut, MaxRandomRanges)},
	}
	for i, r := range ok {
		r := r
		if err := (Options{Random: &r}).Validate(); err != nil {
			t.Fatalf("valid %d: %v", i, err)
		}
	}
	bad := []RandomOptions{
		{TLSRec: []RandomCut{{From: Pos{Offset: 1}, To: Pos{2, true}}}},
		{Split: []RandomCut{{From: Pos{Offset: 9}, To: Pos{Offset: 2}}}},
		{TLSRec: []RandomCut{{Count: -1}}},
		{TLSRec: []RandomCut{{Count: MaxRandomCount + 1}}},
		{Split: []RandomCut{{MinPiece: -1}}},
		{Split: []RandomCut{{MinPiece: DefaultMaxClientHelloSize + 1}}},
		{Split: make([]RandomCut, MaxRandomRanges+1)},
	}
	for i, r := range bad {
		r := r
		err := (Options{Random: &r}).Validate()
		if err == nil || !strings.HasPrefix(err.Error(), "desync: ") {
			t.Fatalf("invalid %d accepted: %v", i, err)
		}
		// An invalid policy is terminal on the first write, never ignored.
		raw := newSegmentSink(t)
		r.TLSRec = append(r.TLSRec, RandomCut{})
		w := WrapConn(raw, Options{Random: &r})
		if _, err := w.Write(framingHello("random.example", 0)); err == nil || len(raw.segs) != 0 {
			t.Fatalf("invalid %d was transmitted: %v", i, err)
		}
	}
	fake := Options{Fake: &FakeOptions{TTL: 4}, Random: &RandomOptions{Split: []RandomCut{{}}}}
	if err := fake.Validate(); err == nil || !strings.Contains(err.Error(), "split") {
		t.Fatalf("fake with random split accepted: %v", err)
	}
}

func TestRandomOptionsAreCopied(t *testing.T) {
	rec := framingHello("random.example", 300)
	policy := RandomOptions{TLSRec: []RandomCut{{From: Pos{-8, true}, To: Pos{8, true}, Count: 2}}, Seed: 11}
	opts := Options{Random: &policy}
	want := randomRun(t, Options{Random: policy.clone()}, rec, len(rec)).data()
	sink := newSegmentSink(t)
	w := WrapConn(sink, opts)
	defer w.Close()
	policy.Seed = 12
	policy.TLSRec[0].Count = 9
	policy.TLSRec = append(policy.TLSRec, RandomCut{From: Pos{Offset: 1}, To: Pos{Offset: 100}})
	if _, err := w.Write(rec); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sink.data(), want) {
		t.Fatal("caller changes altered an existing wrapper")
	}
}

func TestOptionsKey(t *testing.T) {
	base := Options{
		TLSRec:      []Pos{{1, true}, {3, false}},
		Split:       []Pos{{-2, true}},
		SplitDelay:  time.Millisecond,
		ClientHello: &ClientHelloOptions{MaxSize: 1024, MaxRecords: 8, Timeout: time.Second},
		Fake:        &FakeOptions{TTL: 4, Prefix: -1, Payload: []byte{1, 2}, Timeout: time.Second},
		Random: &RandomOptions{
			TLSRec: []RandomCut{{From: Pos{-4, true}, To: Pos{4, true}, Count: 2, MinPiece: 3}},
			Split:  []RandomCut{{From: Pos{Offset: 1}, To: Pos{Offset: 9}}},
			Seed:   5,
		},
	}
	const want = "desync/v1;tlsrec=1+s,3;split=-2+s;delay=1000000;hello=1024,8,1000000000;" +
		"fake=ttl:4,prefix:-1,timeout:1000000000,payload:a12871fee210fb8619291eaea194581cbd2531e4b23759d225f6806923f63222;" +
		"random=seed:5,tlsrec:[-4+s..4+s*2/3],split:[1..9*0/0]"
	if got := base.Key(); got != want {
		t.Fatalf("key changed:\n got %s\nwant %s", got, want)
	}
	if got := (Options{}).Key(); got != "desync/v1;tlsrec=;split=;delay=0;hello=default;fake=off;random=off" {
		t.Fatalf("empty key: %s", got)
	}
	clone := func() Options {
		o := base
		o.TLSRec = append([]Pos(nil), base.TLSRec...)
		o.Split = append([]Pos(nil), base.Split...)
		h, f := *base.ClientHello, *base.Fake
		o.ClientHello, o.Fake, o.Random = &h, &f, base.Random.clone()
		return o
	}
	mutations := []func(*Options){
		func(o *Options) { o.TLSRec[0].Offset = 2 },
		func(o *Options) { o.TLSRec[1].FromSNI = true },
		func(o *Options) { o.Split = nil },
		func(o *Options) { o.SplitDelay = 0 },
		func(o *Options) { o.ClientHello = nil },
		func(o *Options) { o.ClientHello.MaxRecords = 9 },
		func(o *Options) { o.Fake.TTL = 5 },
		func(o *Options) { o.Fake.Payload = []byte{1, 3} },
		func(o *Options) { o.Fake.Payload = nil },
		func(o *Options) { o.Fake = nil },
		func(o *Options) { o.Random = nil },
		func(o *Options) { o.Random.Seed = 0 },
		func(o *Options) { o.Random.Seed = 6 },
		func(o *Options) { o.Random.TLSRec[0].Count = 3 },
		func(o *Options) { o.Random.TLSRec[0].MinPiece = 0 },
		func(o *Options) { o.Random.TLSRec[0].To.Offset = 5 },
		func(o *Options) { o.Random.TLSRec, o.Random.Split = o.Random.Split, o.Random.TLSRec },
		func(o *Options) { o.Random.Split = nil },
	}
	seen := map[string]int{want: -1}
	for i, m := range mutations {
		o := clone()
		m(&o)
		k := o.Key()
		if j, dup := seen[k]; dup {
			t.Fatalf("mutation %d has the key of %d: %s", i, j, k)
		}
		seen[k] = i
	}
	if base.Key() != want {
		t.Fatal("mutations altered the base options")
	}
}

func TestRandomVerifiedTLSHandshake(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
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
	policies := []*RandomOptions{
		{TLSRec: []RandomCut{{From: Pos{-30, true}, To: Pos{10, true}, Count: 6, MinPiece: 2}},
			Split: []RandomCut{{From: Pos{Offset: 1}, To: Pos{Offset: 400}, Count: 5, MinPiece: 20}}},
		{TLSRec: []RandomCut{{From: Pos{Offset: 0}, To: Pos{Offset: 1 << 14}, Count: MaxRandomCount}}, Seed: 77},
	}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(5 * time.Second))
				conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}})
				if conn.Handshake() == nil {
					conn.Write([]byte("ok"))
				}
			}()
		}
	}()
	for i := 0; i < 20; i++ {
		raw, err := net.DialTimeout("tcp4", ln.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		rc := &recConn{Conn: raw}
		w := WrapConn(rc, Options{Random: policies[i%len(policies)]})
		w.SetDeadline(time.Now().Add(5 * time.Second))
		client := tls.Client(w, &tls.Config{ServerName: "www.youtube.com", RootCAs: roots})
		var reply [2]byte
		if _, err = io.ReadFull(client, reply[:]); err != nil || string(reply[:]) != "ok" {
			t.Fatalf("connection %d: %q %v", i, reply, err)
		}
		client.Close()
		rc.mu.Lock()
		segs := rc.segs
		rc.mu.Unlock()
		checkSegments(t, segs)
		if len(segs) < 2 {
			t.Fatalf("connection %d: hello was not transformed", i)
		}
	}
}

// FuzzRandomCuts checks byte preservation, valid framing, non-empty writes,
// range/minimum-piece bounds and seed reproduction for arbitrary policies.
func FuzzRandomCuts(f *testing.F) {
	f.Add(uint64(1), uint8(14), uint16(300), uint16(0), true, int16(-5), uint16(25), uint8(3), uint8(4), false, int16(0), uint16(400), uint8(4), uint8(16), uint8(0), []byte("tail"))
	f.Add(uint64(0), uint8(1), uint16(0), uint16(40), false, int16(0), uint16(9000), uint8(64), uint8(1), true, int16(-200), uint16(300), uint8(64), uint8(0), uint8(1), []byte(nil))
	f.Add(uint64(42), uint8(200), uint16(8000), uint16(7), false, int16(-100), uint16(65535), uint8(17), uint8(250), false, int16(30), uint16(1), uint8(1), uint8(1), uint8(63), []byte{22, 3, 3, 0, 1, 1})
	f.Fuzz(func(t *testing.T, seed uint64, hostLen uint8, padding, reframe uint16,
		recSNI bool, recFrom int16, recWidth uint16, recCount, recMin uint8,
		splitSNI bool, splitFrom int16, splitWidth uint16, splitCount, splitMin uint8,
		chunkByte uint8, tail []byte) {
		host := strings.Repeat("h", 1+int(hostLen)%200)
		rec := framingHello(host, int(padding)%9000)
		wire := rec
		if r := int(reframe) % len(rec[5:]); r > 0 {
			wire = reframeInput(rec, r)
		}
		wire = append(append([]byte(nil), wire...), tail...)
		rc := RandomCut{From: Pos{int(recFrom), recSNI}, Count: int(recCount) % (MaxRandomCount + 1), MinPiece: int(recMin)}
		rc.To = Pos{rc.From.Offset + int(recWidth), recSNI}
		sc := RandomCut{From: Pos{int(splitFrom), splitSNI}, Count: int(splitCount) % (MaxRandomCount + 1), MinPiece: int(splitMin)}
		sc.To = Pos{sc.From.Offset + int(splitWidth), splitSNI}
		opts := Options{Random: &RandomOptions{TLSRec: []RandomCut{rc}, Split: []RandomCut{sc}, Seed: seed}}
		if err := opts.Validate(); err != nil {
			t.Fatal(err)
		}
		chunk := 1 + int(chunkByte)%64
		sink := randomRun(t, opts, wire, chunk)
		checkSegments(t, sink.segs)
		bounds := checkRandomOutput(t, wire, sink.data())
		h, _ := ParseHello(rec)
		sni := h.SNIOffset - recordHeaderLen
		// Without deterministic positions, every boundary is an input
		// boundary or a drawn cut inside the clipped range.
		var scanner helloScanner
		frame, _ := scanner.scan(wire, (*ClientHelloOptions)(nil).limits())
		lo, hi := frame.logicalAt(rc.From.Offset), frame.logicalAt(rc.To.Offset)
		if recSNI {
			lo, hi = sni+rc.From.Offset, sni+rc.To.Offset
		}
		existing := map[int]bool{}
		for i, logical := 1, 0; i < frame.records.count; i++ {
			r := frame.records.at(i - 1)
			logical += r.end - r.start - recordHeaderLen
			existing[logical] = true
		}
		gap := rc.MinPiece
		if gap < 1 {
			gap = 1
		}
		prev := -1
		drawn := 0
		for _, b := range bounds {
			if existing[b] {
				continue
			}
			drawn++
			if b < lo || b > hi || b < gap || b > frame.size-gap {
				t.Fatalf("cut %d outside [%d,%d] gap=%d size=%d", b, lo, hi, gap, frame.size)
			}
			if prev >= 0 && b-prev < gap {
				t.Fatalf("cuts %d and %d closer than %d", prev, b, gap)
			}
			prev = b
		}
		want := rc.Count
		if want == 0 {
			want = 1
		}
		if drawn > want {
			t.Fatalf("%d cuts drawn, at most %d requested", drawn, want)
		}
		if seed != 0 {
			again := randomRun(t, opts, wire, len(wire))
			if !bytes.Equal(again.data(), sink.data()) {
				t.Fatal("seeded output not reproduced")
			}
		}
	})
}
