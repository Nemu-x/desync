//go:build !linux && !windows && !darwin

package desync

const autoTTLReason = "observing the server's TTL is not implemented on this platform"
