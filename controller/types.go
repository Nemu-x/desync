// Package controller selects opaque strategy IDs using explicitly supplied,
// application-aware probes. It owns no sockets, application payloads or routing.
package controller

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"
)

// Verification describes what the caller's probe actually verified. A TCP
// connection alone never qualifies. TLS verifies the intended peer; Application
// additionally verifies the configured application response.
type Verification uint8

const (
	Unknown Verification = iota
	TCP
	TLS
	Application
)

// Target includes the network fingerprint and the caller-defined probe contract.
// ProbeID identifies that contract, not a URL to be fetched by this package.
type Target struct {
	Network  string
	Host     string
	Port     uint16
	ProbeID  string
	Required Verification
}

type Proof struct {
	Level Verification
	Code  string
}
type Prober interface {
	Probe(context.Context, Target, string) (Proof, error)
}
type ProbeFunc func(context.Context, Target, string) (Proof, error)

func (f ProbeFunc) Probe(ctx context.Context, t Target, id string) (Proof, error) {
	return f(ctx, t, id)
}

// Config is copied at construction. Candidate IDs must refer to immutable
// caller-owned options; change PolicyVersion when that catalog or probe changes.
// Zero values select documented defaults, except StaleTTL (disabled) and booleans.
type Config struct {
	Candidates                                          []string
	PolicyVersion                                       string
	CacheTTL, NegativeTTL, StaleTTL                     time.Duration
	ProbeTimeout, DiscoveryTimeout, RevalidateAfter     time.Duration
	MaxConcurrentProbes, MaxParallelProbes, MaxAttempts int
	MaxEntries, MaxDiscoveries, HistoryLimit            int
	BackgroundRevalidate                                bool
	BackgroundConcurrency                               int
	DisableDiscovery                                    bool
	// Now affects cache timestamps only. It must be fast, nonblocking and safe
	// for concurrent use; it must not call back into this controller.
	Now func() time.Time
}

type SelectOptions struct {
	// Manual is an explicit, unverified override. It never invokes a probe.
	Manual string
	// Refresh bypasses positive/negative cache and candidate cooldowns, while
	// retaining deduplication, deadlines and the finite attempt budget.
	Refresh bool
}

type Selection struct {
	Strategy                                        string
	Source                                          string // probe, cache, stale or manual
	Level                                           Verification
	VerifiedAt, ExpiresAt                           time.Time
	CacheHit, Stale                                 bool
	ProbeDuration, QueueDuration, DiscoveryDuration time.Duration
	ProbeAttempts                                   int
}

var (
	ErrClosed            = errors.New("controller closed")
	ErrDiscoveryDisabled = errors.New("automatic discovery disabled")
	ErrNoStrategy        = errors.New("no verified strategy")
	ErrNegativeCached    = errors.New("negative result cached")
	ErrCapacity          = errors.New("controller capacity reached")
	ErrInvalidated       = errors.New("selection invalidated")
	ErrBusy              = errors.New("cannot restore during discovery")
)

func normalize(t Target) (Target, error) {
	if !token(t.Network, 128) || !token(t.ProbeID, 128) || t.Port == 0 {
		return t, fmt.Errorf("invalid target identity")
	}
	t.Host = strings.TrimSpace(t.Host)
	if strings.ContainsAny(t.Host, "@/\\?#[]") || strings.IndexFunc(t.Host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return t, fmt.Errorf("invalid target host")
	}
	// Avoid allocating a netip parse error on every normal hostname cache hit.
	var ip netip.Addr
	if strings.Contains(t.Host, ":") || numericHost(t.Host) {
		ip, _ = netip.ParseAddr(t.Host)
	}
	if ip.IsValid() {
		t.Host = ip.Unmap().String()
	} else {
		t.Host = strings.ToLower(strings.TrimRight(t.Host, "."))
		if t.Host == "" || len(t.Host) > 253 || strings.ContainsAny(t.Host, "@/\\?#:[]") || strings.IndexFunc(t.Host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return t, fmt.Errorf("invalid target host")
		}
	}
	if t.Required == Unknown {
		t.Required = Application
	}
	if t.Required != TLS && t.Required != Application {
		return t, fmt.Errorf("TLS or application proof required")
	}
	return t, nil
}

func numericHost(host string) bool {
	for i := 0; i < len(host); i++ {
		if host[i] != '.' && (host[i] < '0' || host[i] > '9') {
			return false
		}
	}
	return host != ""
}

func token(s string, max int) bool {
	return s != "" && len(s) <= max && strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) < 0
}

func defaults(c Config) (Config, error) {
	if !token(c.PolicyVersion, 128) || len(c.Candidates) == 0 || len(c.Candidates) > 256 {
		return c, fmt.Errorf("policy version and 1..256 candidates required")
	}
	c.Candidates = append([]string(nil), c.Candidates...)
	seen := make(map[string]bool)
	for _, id := range c.Candidates {
		if !token(id, 128) || seen[id] {
			return c, fmt.Errorf("invalid or duplicate strategy ID")
		}
		seen[id] = true
	}
	durations := []struct {
		p        *time.Duration
		def, max time.Duration
	}{
		{&c.CacheTTL, 30 * time.Minute, 7 * 24 * time.Hour}, {&c.NegativeTTL, 30 * time.Second, time.Hour},
		{&c.ProbeTimeout, 2 * time.Second, time.Minute}, {&c.DiscoveryTimeout, 10 * time.Second, 5 * time.Minute},
	}
	for _, v := range durations {
		if *v.p == 0 {
			*v.p = v.def
		}
		if *v.p < 0 || *v.p > v.max {
			return c, fmt.Errorf("duration out of range")
		}
	}
	if c.StaleTTL < 0 || c.StaleTTL > 24*time.Hour {
		return c, fmt.Errorf("stale TTL out of range")
	}
	if c.RevalidateAfter == 0 {
		c.RevalidateAfter = c.CacheTTL / 2
	}
	if c.RevalidateAfter < 0 || c.RevalidateAfter > c.CacheTTL {
		return c, fmt.Errorf("revalidation age out of range")
	}
	ints := []struct {
		p        *int
		def, max int
	}{
		{&c.MaxConcurrentProbes, 2, 64}, {&c.MaxParallelProbes, 2, 16}, {&c.MaxAttempts, 8, 256},
		{&c.MaxEntries, 512, 16384}, {&c.MaxDiscoveries, 64, 1024}, {&c.HistoryLimit, 64, 4096},
		{&c.BackgroundConcurrency, 1, 64},
	}
	for _, v := range ints {
		if *v.p == 0 {
			*v.p = v.def
		}
		if *v.p < 1 || *v.p > v.max {
			return c, fmt.Errorf("limit out of range")
		}
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c, nil
}
