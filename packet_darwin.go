//go:build darwin

package desync

// suppressUDPErrors has nothing to do on macOS: udp_ctlinput delivers an ICMP
// error only to a socket whose foreign address and port match exactly
// (in_pcblookup_hash without wildcard), so an unconnected socket never sees
// the time-exceeded replies to the low-TTL datagrams.
func suppressUDPErrors(uintptr) error { return nil }
