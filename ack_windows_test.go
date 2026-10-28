//go:build windows

package desync

import (
	"io"
	"testing"
	"time"
)

func TestTCPInfoV0Layout(t *testing.T) {
	b := make([]byte, tcpInfoV0Size)
	b[28], b[29] = 0x34, 0x12 // BytesInFlight
	b[48], b[55] = 0x05, 0x01 // BytesOut
	b[68] = 0x02              // BytesRetrans
	got := parseTCPInfoV0(b)
	if got.inFlight != 0x1234 || got.out != 1<<56|5 || got.retrans != 2 || got.distinctOut() != 1<<56|3 {
		t.Fatalf("parsed %+v", got)
	}
	if (tcpInfoV0{out: 1, retrans: 2}).distinctOut() != 0 {
		t.Fatal("distinct count underflowed")
	}
}

// Small writes, the size of ClientHello pieces: the counter advances by
// exactly the written bytes and the wait is not satisfied by unwritten ones.
func TestWindowsAckCountsSmallWrites(t *testing.T) {
	for _, size := range []int{1, 517, 1400, 16 << 10} {
		client, server := loopbackPair(t, "tcp4")
		raw, err := client.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		obs, err := newAckObserver(raw)
		if err != nil {
			t.Fatal(err)
		}
		go io.ReadFull(server, make([]byte, 2*size))
		for round := 1; round <= 2; round++ {
			if _, err := client.Write(make([]byte, size)); err != nil {
				t.Fatal(err)
			}
			written := int64(round * size)
			end := time.Now().Add(5 * time.Second)
			for {
				done, err := obs.reached(SplitWaitAcked, written)
				if err != nil {
					t.Fatal(err)
				}
				if done {
					break
				}
				if time.Now().After(end) {
					t.Fatalf("size %d: not acknowledged", size)
				}
				time.Sleep(time.Millisecond)
			}
			if done, _ := obs.reached(SplitWaitSent, written+1); done {
				state, _ := obs.state()
				t.Fatalf("size %d: an unwritten byte counted as sent: %+v", size, state)
			}
		}
	}
}
