//go:build !android

package desync

// sentPerSocket is false: where SplitWaitSent is implemented, this OS lets
// every socket report its unsent bytes (see capability_android.go).
const sentPerSocket = false

const sentPerSocketReason = ""
