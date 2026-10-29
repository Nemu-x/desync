package presets

import (
	"fmt"

	"github.com/Nemu-x/desync"
)

// Ranks of the TCP catalog, lower first. The order puts strategies that add no
// packets, no delay and no TTL guess before those that do: a record split is
// one ordinary write; a write split adds a segment; a split wait adds up to a
// round trip; disorder costs a retransmission and the out-of-band byte relies
// on the server discarding urgent data; a fake depends on a TTL that expires
// between the filter and the server, and breaks the handshake when it reaches
// the server, so it is tried last, combinations after single fakes.
const (
	rankBaseline = 0
	rankRecord   = 10
	rankSplit    = 20
	rankWait     = 30
	rankDisorder = 40
	rankFake     = 50
	rankCombo    = 60
)

// Ranks of the UDP catalog: fewer extra datagrams first.
const (
	// defaultUDPRepeats is what UDPOptions.Repeats zero means.
	defaultUDPRepeats = 6

	rankUDPLight   = 10
	rankUDPDefault = 20
	rankUDPHeavy   = 30
)

func pos(s string) desync.Pos {
	p, err := desync.ParsePos(s)
	if err != nil {
		panic(err)
	}
	return p
}

func posList(ss ...string) []desync.Pos {
	out := make([]desync.Pos, len(ss))
	for i, s := range ss {
		out[i] = pos(s)
	}
	return out
}

// TCP returns every built-in TCP preset, independent of the platform, in a
// stable order (the order of desync-probe reports); the baseline is first. The
// result is a fresh copy. Use Available for the presets of this system and
// Ranked for the suggested order of trying them.
func TCP() []Preset {
	fake := func(ttl int) Preset {
		return Preset{
			Name:        fmt.Sprintf("fake-ttl%d", ttl),
			Description: fmt.Sprintf("low-TTL fake first transmission of all but the last byte, TTL %d", ttl),
			Options:     desync.Options{Fake: &desync.FakeOptions{TTL: ttl, Prefix: -1}},
			Needs:       []Feature{FeatureFakeTCP},
			Rank:        rankFake,
		}
	}
	return []Preset{
		{Name: BaselineName, Description: "direct connection, no transformation (baseline)", Rank: rankBaseline},
		{Name: "tlsrec-1s", Description: "TLS records split 1 byte into the server name (--tlsrec 1+s)",
			Options: desync.Options{TLSRec: posList("1+s")}, Rank: rankRecord},
		{Name: "tlsrec-3s", Description: "TLS records split 3 bytes into the server name (--tlsrec 3+s)",
			Options: desync.Options{TLSRec: posList("3+s")}, Rank: rankRecord},
		{Name: "tlsrec-before-sni", Description: "TLS records split 2 bytes before the server name (--tlsrec -2+s)",
			Options: desync.Options{TLSRec: posList("-2+s")}, Rank: rankRecord},
		{Name: "tlsrec-multi", Description: "TLS records split at 1+s, 5+s and 10+s",
			Options: desync.Options{TLSRec: posList("1+s", "5+s", "10+s")}, Rank: rankRecord},
		{Name: "split-1", Description: "TCP writes split after byte 1 (--split 1)",
			Options: desync.Options{Split: posList("1")}, Rank: rankSplit},
		{Name: "split-1s", Description: "TCP writes split 1 byte into the server name (--split 1+s)",
			Options: desync.Options{Split: posList("1+s")}, Rank: rankSplit},
		{Name: "tlsrec-1s-split-1", Description: "TLS records at 1+s and TCP writes split after byte 1",
			Options: desync.Options{TLSRec: posList("1+s"), Split: posList("1")}, Rank: rankSplit},
		{Name: "random-tlsrec", Description: "two random TLS record cuts within 8 bytes of the server name, new cuts per connection",
			Options: desync.Options{Random: &desync.RandomOptions{TLSRec: []desync.RandomCut{{From: pos("-8+s"), To: pos("8+s"), Count: 2, MinPiece: 2}}}},
			Rank:    rankRecord},
		{Name: "random-split", Description: "one random TCP write cut between bytes 1 and 120, new cut per connection",
			Options: desync.Options{Random: &desync.RandomOptions{Split: []desync.RandomCut{{From: pos("1"), To: pos("120")}}}},
			Rank:    rankSplit},
		{Name: "disorder-1", Description: "split after byte 1, first piece sent with hop limit 1 (--disorder 1)",
			Options: desync.Options{Split: posList("1"), Disorder: true}, Needs: []Feature{FeatureDisorder}, Rank: rankDisorder},
		{Name: "disorder-1s", Description: "split at 1+s, first piece sent with hop limit 1 (--disorder 1+s)",
			Options: desync.Options{Split: posList("1+s"), Disorder: true}, Needs: []Feature{FeatureDisorder}, Rank: rankDisorder},
		{Name: "oob-1", Description: "split after byte 1 with one out-of-band byte (--oob 1)",
			Options: desync.Options{Split: posList("1"), OOB: &desync.OOBOptions{}}, Needs: []Feature{FeatureOOB}, Rank: rankDisorder},
		{Name: "oob-1s", Description: "split at 1+s with one out-of-band byte (--oob 1+s)",
			Options: desync.Options{Split: posList("1+s"), OOB: &desync.OOBOptions{}}, Needs: []Feature{FeatureOOB}, Rank: rankDisorder},
		{Name: "disoob-1s", Description: "split at 1+s, hop limit 1 and an out-of-band byte (--disoob 1+s)",
			Options: desync.Options{Split: posList("1+s"), Disorder: true, OOB: &desync.OOBOptions{}},
			Needs:   []Feature{FeatureDisorder, FeatureOOB}, Rank: rankDisorder},
		{Name: "split-1s-wait-sent", Description: "split at 1+s, second piece only after the first was transmitted",
			Options: desync.Options{Split: posList("1+s"), SplitWait: desync.SplitWaitSent},
			Needs:   []Feature{FeatureSplitWaitSent}, Rank: rankWait},
		{Name: "split-1s-wait-acked", Description: "split at 1+s, second piece only after the first was acknowledged",
			Options: desync.Options{Split: posList("1+s"), SplitWait: desync.SplitWaitAcked},
			Needs:   []Feature{FeatureSplitWaitAcked}, Rank: rankWait},
		fake(3),
		fake(5),
		fake(8),
		{Name: "fake-ttl5-sni", Description: "low-TTL fake whose decoy ClientHello names www.wikipedia.org, randomized per connection, TTL 5",
			Options: desync.Options{Fake: &desync.FakeOptions{TTL: 5, Prefix: -1, SNI: []string{"www.wikipedia.org"}, Randomize: true}},
			Needs:   []Feature{FeatureFakeTCP}, Rank: rankFake},
		{Name: "split-1s-fake-ttl5", Description: "split at 1+s, the piece from there to the last byte sent first as a low-TTL fake, TTL 5",
			Options: desync.Options{Split: posList("1+s"), Fake: &desync.FakeOptions{TTL: 5, Prefix: -1}},
			Needs:   []Feature{FeatureFakeTCP}, Rank: rankFake},
		{Name: "disorder-1-fake-ttl5", Description: "split after byte 1 with hop limit 1 on the first piece, the rest sent first as a low-TTL fake, TTL 5",
			Options: desync.Options{Split: posList("1"), Disorder: true, Fake: &desync.FakeOptions{TTL: 5, Prefix: -1}},
			Needs:   []Feature{FeatureDisorder, FeatureFakeTCP}, Rank: rankCombo},
	}
}

// UDP returns every built-in UDP burst preset, independent of the platform, in
// a stable order. The result is a fresh copy. Zero-payload bursts (ByeDPI's
// UDP fake) precede every initial datagram; QUIC Initial decoys go only before
// datagrams that look like a QUIC client Initial, so other UDP traffic, such
// as voice media, is untouched by them.
func UDP() []UDPPreset {
	zero := func(ttl, repeats, rank int) UDPPreset {
		name, n := fmt.Sprintf("udp-zero-ttl%d", ttl), defaultUDPRepeats
		if repeats != 0 {
			name, n = fmt.Sprintf("%s-r%d", name, repeats), repeats
		}
		return UDPPreset{
			Name:        name,
			Description: fmt.Sprintf("%d low-TTL datagrams of 64 zero bytes before each of the first 3 datagrams to a peer, TTL %d", n, ttl),
			Options:     desync.UDPOptions{TTL: ttl, Repeats: repeats},
			Needs:       []Feature{FeatureFakeUDP},
			Rank:        rank,
		}
	}
	quic := func(ttl, repeats, rank int) UDPPreset {
		name, n := fmt.Sprintf("udp-quic-ttl%d", ttl), defaultUDPRepeats
		if repeats != 0 {
			name, n = fmt.Sprintf("%s-r%d", name, repeats), repeats
		}
		return UDPPreset{
			Name: name,
			Description: fmt.Sprintf("%d low-TTL QUIC Initial decoys naming %s before each of the first 3 QUIC Initials to a peer, other UDP untouched, TTL %d",
				n, desync.DefaultQUICSNI, ttl),
			Options: desync.UDPOptions{TTL: ttl, Repeats: repeats, Template: desync.UDPTemplateQUICInitial, QUICOnly: true},
			Needs:   []Feature{FeatureFakeUDP},
			Rank:    rank,
		}
	}
	return []UDPPreset{
		zero(3, 0, rankUDPDefault),
		zero(5, 0, rankUDPDefault),
		zero(8, 0, rankUDPDefault),
		zero(5, 2, rankUDPLight),
		zero(5, 12, rankUDPHeavy),
		quic(3, 0, rankUDPDefault),
		quic(5, 0, rankUDPDefault),
		quic(8, 0, rankUDPDefault),
		quic(5, 2, rankUDPLight),
	}
}
