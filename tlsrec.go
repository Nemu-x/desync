package desync

// FragmentRecord splits one TLS record into several records at the given
// absolute offsets (header included in the numbering, like ParseHello's
// offsets). Every piece gets its own 5-byte header with the original content
// type and version, so the peer reassembles the same handshake message; a DPI
// box that only reads the first record no longer sees the whole ClientHello.
// Offsets outside the payload are ignored; rec is not modified.
func FragmentRecord(rec []byte, cuts []int) []byte {
	if len(rec) < recordHeaderLen {
		return append([]byte(nil), rec...)
	}
	var at []int
	for _, c := range cuts {
		if c > recordHeaderLen && c < len(rec) {
			at = append(at, c)
		}
	}
	if len(at) == 0 {
		return append([]byte(nil), rec...)
	}
	out := make([]byte, 0, len(rec)+recordHeaderLen*len(at))
	start := recordHeaderLen
	for _, end := range append(at, len(rec)) {
		if end <= start {
			continue
		}
		n := end - start
		out = append(out, rec[0], rec[1], rec[2], byte(n>>8), byte(n))
		out = append(out, rec[start:end]...)
		start = end
	}
	return out
}
