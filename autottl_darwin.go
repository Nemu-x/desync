//go:build darwin

package desync

// xnu's tcp_input never saves received IP control data (no ip_savecontrol or
// ip6_savecontrol call), and ip6_ctloutput answers getsockopt
// IPV6_2292PKTOPTIONS with empty data.
const autoTTLReason = "xnu TCP keeps no received IP control data (tcp_input saves none, and getsockopt IPV6_2292PKTOPTIONS always returns empty data)"
