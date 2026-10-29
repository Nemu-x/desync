//go:build !linux

package desync

import "fmt"

// No unprivileged interface reports the TTL of a TCP socket's received
// packets here; autoTTLReason (per OS) says why.
var platformAutoTTL = AutoTTLCapability{}

const (
	autoTTLIPv4Reason = autoTTLReason
	autoTTLIPv6Reason = autoTTLReason
)

func prepareTTLObservation(uintptr, string) error { return nil }

func observeTTL(uintptr, bool) (int, error) {
	return 0, fmt.Errorf("%w: %s", ErrAutoTTLUnsupported, autoTTLReason)
}
