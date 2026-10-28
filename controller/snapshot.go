package controller

import (
	"sort"
	"time"
)

const SnapshotVersion = 1

// Snapshot is caller-owned persistence. Export/Restore perform no file I/O.
// Treat it as potentially sensitive: network/host/probe identities are explicit.
type Snapshot struct {
	Version       int
	PolicyVersion string
	Entries       []CachedTarget
}

type CachedTarget struct {
	Target         Target
	Selection      Selection
	NegativeUntil  time.Time
	NegativeReason string
	Candidates     []CandidateStats
}

func (c *Controller) Export() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Snapshot{Version: SnapshotVersion, PolicyVersion: c.cfg.PolicyVersion}
	for t, e := range c.entries {
		x := CachedTarget{Target: t, Selection: e.selected, NegativeUntil: e.negativeUntil, NegativeReason: e.negativeReason}
		for _, id := range c.cfg.Candidates {
			if v := e.stats[id]; v != nil {
				x.Candidates = append(x.Candidates, *v)
			}
		}
		s.Entries = append(s.Entries, x)
	}
	sort.Slice(s.Entries, func(i, j int) bool {
		a, b := s.Entries[i].Target, s.Entries[j].Target
		if a.Network != b.Network {
			return a.Network < b.Network
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.ProbeID != b.ProbeID {
			return a.ProbeID < b.ProbeID
		}
		return a.Required < b.Required
	})
	return s
}

// Restore validates the entire snapshot before replacing cache state. Expiration
// and cooldowns are clamped to current policy. A changed PolicyVersion is rejected.
func (c *Controller) Restore(s Snapshot) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClosed
	}
	if len(c.flights) > 0 {
		return ErrBusy
	}
	if s.Version != SnapshotVersion || s.PolicyVersion != c.cfg.PolicyVersion || len(s.Entries) > c.cfg.MaxEntries {
		return fmtError("incompatible snapshot")
	}
	now := c.cfg.Now()
	entries := make(map[Target]*entry, len(s.Entries))
	var used uint64
	clamp := func(v time.Time, max time.Duration) time.Time {
		if v.After(now.Add(max)) {
			return now.Add(max)
		}
		return v
	}
	for _, x := range s.Entries {
		t, err := normalize(x.Target)
		if err != nil {
			return err
		}
		if entries[t] != nil || len(x.Candidates) > len(c.cfg.Candidates) {
			return fmtError("invalid snapshot entry")
		}
		e := &entry{stats: make(map[string]*CandidateStats), negativeUntil: clamp(x.NegativeUntil, c.cfg.NegativeTTL)}
		if x.NegativeReason != "" && !token(x.NegativeReason, 64) {
			return fmtError("invalid negative reason")
		}
		e.negativeReason = x.NegativeReason
		v := x.Selection
		if v.Strategy != "" {
			if !c.ids[v.Strategy] || v.Level < t.Required || v.Level > Application || v.VerifiedAt.IsZero() || v.VerifiedAt.After(now) || !v.ExpiresAt.After(v.VerifiedAt) || v.ProbeDuration < 0 || v.QueueDuration < 0 || v.DiscoveryDuration < 0 || v.ProbeAttempts < 0 || v.ProbeAttempts > 256 {
				return fmtError("invalid cached proof")
			}
			maxExpiry := v.VerifiedAt.Add(c.cfg.CacheTTL)
			if v.ExpiresAt.After(maxExpiry) {
				v.ExpiresAt = maxExpiry
			}
			v.Source = "probe"
			v.CacheHit = false
			v.Stale = false
			e.selected = v
		}
		for _, v := range x.Candidates {
			if !c.ids[v.Strategy] || e.stats[v.Strategy] != nil || v.LastVerified.After(now) || v.LastDuration < 0 || v.EWMA < 0 || (v.LastCode != "" && !token(v.LastCode, 64)) {
				return fmtError("invalid candidate history")
			}
			v.NegativeUntil = clamp(v.NegativeUntil, c.cfg.NegativeTTL)
			copy := v
			e.stats[v.Strategy] = &copy
		}
		used++
		e.used = used
		entries[t] = e
	}
	c.entries = entries
	c.clock = used
	c.history = nil
	return nil
}
