package desync

import (
	"net"
	"testing"
)

func benchmarkFirstWrite(b *testing.B, opts Options) {
	a, peer := net.Pipe()
	defer a.Close()
	defer peer.Close()
	sink := &framingDiscard{a}
	rec := framingHello("fragment.example", 420)
	b.ReportAllocs()
	b.SetBytes(int64(len(rec)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := WrapConn(sink, opts)
		if _, err := w.Write(rec); err != nil {
			b.Fatal(err)
		}
		// A later write is the warm path and must stay allocation-free.
		if _, err := w.Write(rec[:16]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFirstWriteDeterministic(b *testing.B) {
	benchmarkFirstWrite(b, Options{
		TLSRec: []Pos{{Offset: 1, FromSNI: true}, {Offset: 40}},
		Split:  []Pos{{Offset: 3, FromSNI: true}},
	})
}

var benchRandomCuts = []RandomCut{{From: Pos{-4, true}, To: Pos{12, true}, Count: 2, MinPiece: 2}}
var benchRandomSplit = []RandomCut{{From: Pos{0, true}, To: Pos{8, true}}}

func BenchmarkFirstWriteRandomSeeded(b *testing.B) {
	benchmarkFirstWrite(b, Options{
		TLSRec: []Pos{{Offset: 40}},
		Random: &RandomOptions{TLSRec: benchRandomCuts, Split: benchRandomSplit, Seed: 1},
	})
}

func BenchmarkFirstWriteRandomUnseeded(b *testing.B) {
	benchmarkFirstWrite(b, Options{
		TLSRec: []Pos{{Offset: 40}},
		Random: &RandomOptions{TLSRec: benchRandomCuts, Split: benchRandomSplit},
	})
}
