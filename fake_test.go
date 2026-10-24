package desync

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestFakeTemplateAndPadding(t *testing.T) {
	data := defaultFakeTLS()
	h, err := ParseHello(data)
	if err != nil || len(data) != 517 || h.SNI != "www.wikipedia.org" {
		t.Fatalf("template: %+v %v, len=%d", h, err, len(data))
	}
	padded := fakePayload([]byte{1, 2}, 5)
	if !bytes.Equal(padded, []byte{1, 2, 0, 0, 0}) {
		t.Fatalf("padding: %v", padded)
	}
	if !bytes.Equal(fakePayload([]byte{1, 2, 3}, 2), []byte{1, 2}) {
		t.Fatal("payload was not truncated")
	}
	data[0] = 0
	if defaultFakeTLS()[0] != 0x16 {
		t.Fatal("template is shared with callers")
	}
}

func TestFakePrefix(t *testing.T) {
	for _, pos := range []int{0, -1, 99} {
		n, err := fakePrefixLength(100, pos)
		if err != nil || n != 99 {
			t.Fatalf("prefix %d: %d, %v", pos, n, err)
		}
	}
	for _, pos := range []int{-100, 100, 101, -101} {
		if _, err := fakePrefixLength(100, pos); err == nil {
			t.Fatalf("accepted prefix %d", pos)
		}
	}
}

func TestFakeValidation(t *testing.T) {
	for _, ttl := range []int{-1, 0, 256} {
		if err := (Options{Fake: &FakeOptions{TTL: ttl}}).Validate(); err == nil {
			t.Fatalf("accepted TTL %d", ttl)
		}
	}
	if err := (Options{Fake: &FakeOptions{TTL: 4, Timeout: -time.Second}}).Validate(); err == nil {
		t.Fatal("accepted negative timeout")
	}
	if err := (Options{Fake: &FakeOptions{TTL: 4}, Split: []Pos{{Offset: 1}}}).Validate(); err == nil {
		t.Fatal("accepted unsupported fake + split")
	}
}

func TestFakeConfigurationIsCopied(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	fake := &FakeOptions{TTL: 4, Payload: []byte{1, 2, 3}}
	opts := Options{TLSRec: []Pos{{Offset: 1}}, Fake: fake}
	w := WrapConn(a, opts).(*Conn)
	opts.TLSRec[0].Offset = 99
	fake.TTL = 8
	fake.Payload[0] = 9
	if w.opts.Fake.TTL != 4 || w.opts.Fake.Payload[0] != 1 || w.opts.TLSRec[0].Offset != 1 {
		t.Fatal("wrapper shares mutable options")
	}
}

func TestFakeUnavailableDoesNotFailOpen(t *testing.T) {
	rec := captureHello(t, "example.test")
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	w := WrapConn(a, Options{Fake: &FakeOptions{TTL: 4}})
	_, err := w.Write(rec)
	want := ErrFakeRequiresTCP
	if !SupportsFake() {
		want = ErrFakeUnsupported
	}
	if !errors.Is(err, want) {
		t.Fatalf("first Write: %v, want %v", err, want)
	}
	if _, second := w.Write([]byte("must not pass")); !errors.Is(second, want) {
		t.Fatalf("later Write: %v", second)
	}
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	n, readErr := b.Read(make([]byte, 8))
	if n != 0 || readErr != io.EOF {
		t.Fatalf("stream after failed fake: n=%d err=%v", n, readErr)
	}
}

type limitedWriter struct {
	data []byte
	zero bool
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.zero {
		return 0, nil
	}
	n := len(p)
	if n > 2 {
		n = 2
	}
	w.data = append(w.data, p[:n]...)
	return n, nil
}

func TestFirstWriteHandlesShortWrites(t *testing.T) {
	w := &limitedWriter{}
	if err := writeAll(w, []byte("abcdef")); err != nil || string(w.data) != "abcdef" {
		t.Fatalf("short writes: %q %v", w.data, err)
	}
	if err := writeAll(&limitedWriter{zero: true}, []byte{1}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero Write: %v", err)
	}
}
