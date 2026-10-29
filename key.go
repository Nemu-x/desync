package desync

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// keyVersion changes whenever the meaning of an unchanged Options value
// changes, including how a seed maps to random cuts.
const keyVersion = "desync/v1"

// Key returns a stable, canonical description of every field that affects
// the transformation, including the randomization policy and seed. Consumers
// that cache strategies by ID (for example with the controller package) should
// derive the ID or PolicyVersion from Key, so a cached ID never silently
// changes meaning. Equal keys mean identical behavior for this library version
// prefix; different keys may still behave alike (for example a nil
// ClientHello and its explicit defaults). The fake payload is represented by
// its SHA-256 digest rather than its bytes.
func (o Options) Key() string {
	var b strings.Builder
	b.WriteString(keyVersion)
	b.WriteString(";tlsrec=")
	writePosList(&b, o.TLSRec)
	b.WriteString(";split=")
	writePosList(&b, o.Split)
	b.WriteString(";delay=")
	b.WriteString(strconv.FormatInt(int64(o.SplitDelay), 10))
	b.WriteString(";hello=")
	if h := o.ClientHello; h == nil {
		b.WriteString("default")
	} else {
		b.WriteString(strconv.Itoa(h.MaxSize))
		b.WriteByte(',')
		b.WriteString(strconv.Itoa(h.MaxRecords))
		b.WriteByte(',')
		b.WriteString(strconv.FormatInt(int64(h.Timeout), 10))
	}
	b.WriteString(";fake=")
	if f := o.Fake; f == nil {
		b.WriteString("off")
	} else {
		b.WriteString("ttl:")
		b.WriteString(strconv.Itoa(f.TTL))
		b.WriteString(",prefix:")
		b.WriteString(strconv.Itoa(f.Prefix))
		b.WriteString(",timeout:")
		b.WriteString(strconv.FormatInt(int64(f.Timeout), 10))
		b.WriteString(",payload:")
		if len(f.Payload) == 0 {
			b.WriteString("default")
		} else {
			sum := sha256.Sum256(f.Payload)
			b.WriteString(hex.EncodeToString(sum[:]))
		}
		// Only when set, so keys of fixed-TTL fakes are unchanged.
		writeAutoTTL(&b, f.AutoTTL)
		// Decoy options are appended only when set, so keys of options
		// without them are unchanged. Validated names contain no ',' or '|'.
		if len(f.SNI) > 0 {
			b.WriteString(",sni:")
			b.WriteString(strings.Join(f.SNI, "|"))
		}
		if f.FromOriginal {
			b.WriteString(",orig:1")
		}
		if f.Randomize {
			b.WriteString(",rand:1")
		}
		if f.Offset != 0 {
			b.WriteString(",offset:")
			b.WriteString(strconv.Itoa(f.Offset))
		}
	}
	b.WriteString(";random=")
	if r := o.Random; r == nil {
		b.WriteString("off")
	} else {
		b.WriteString("seed:")
		if r.Seed == 0 {
			b.WriteString("crypto")
		} else {
			b.WriteString(strconv.FormatUint(r.Seed, 10))
		}
		b.WriteString(",tlsrec:")
		writeRandomList(&b, r.TLSRec)
		b.WriteString(",split:")
		writeRandomList(&b, r.Split)
	}
	// Appended only when set, so keys of options without it are unchanged.
	if o.SplitWait != SplitWaitNone || o.SplitWaitTimeout != 0 {
		b.WriteString(";wait=")
		b.WriteString(o.SplitWait.String())
		b.WriteString(",timeout:")
		b.WriteString(strconv.FormatInt(int64(o.SplitWaitTimeout), 10))
	}
	if o.Disorder {
		b.WriteString(";disorder=1")
	}
	if o.OOB != nil {
		b.WriteString(";oob=")
		b.WriteString(strconv.Itoa(int(o.OOB.urgentByte())))
	}
	return b.String()
}

func writePosList(b *strings.Builder, ps []Pos) {
	for i, p := range ps {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(p.String())
	}
}

// writeRandomList writes "[from..to*count/minpiece ...]".
func writeRandomList(b *strings.Builder, cuts []RandomCut) {
	b.WriteByte('[')
	for i, c := range cuts {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(c.From.String())
		b.WriteString("..")
		b.WriteString(c.To.String())
		b.WriteByte('*')
		b.WriteString(strconv.Itoa(c.Count))
		b.WriteByte('/')
		b.WriteString(strconv.Itoa(c.MinPiece))
	}
	b.WriteByte(']')
}
