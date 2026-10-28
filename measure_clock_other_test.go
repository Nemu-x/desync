//go:build !windows

package desync

import "time"

func preciseClock() func() time.Duration {
	start := time.Now()
	return func() time.Duration { return time.Since(start) }
}
