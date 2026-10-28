package controller

import (
	"context"
	"sync"
	"time"
)

type entry struct {
	selected                      Selection
	negativeUntil, nextBackground time.Time
	negativeReason                string
	stats                         map[string]*CandidateStats
	generation                    uint64
	used                          uint64
}

type flight struct {
	ctx                 context.Context
	cancel              context.CancelFunc
	done                chan struct{}
	entry               *entry
	generation          uint64
	waiters             int
	background, refresh bool
	result              Selection
	err                 error
}

type Controller struct {
	mu         sync.Mutex
	cfg        Config
	prober     Prober
	ids        map[string]bool
	entries    map[Target]*entry
	flights    map[Target]*flight
	history    []Attempt
	clock      uint64
	background int
	closed     bool
	root       context.Context
	cancel     context.CancelFunc
	sem        chan struct{}
	wg         sync.WaitGroup
	done       chan struct{}
}

func New(cfg Config, p Prober) (*Controller, error) {
	cfg, err := defaults(cfg)
	if err != nil {
		return nil, err
	}
	if p == nil && !cfg.DisableDiscovery {
		return nil, fmtError("prober required when discovery is enabled")
	}
	root, cancel := context.WithCancel(context.Background())
	c := &Controller{cfg: cfg, prober: p, ids: make(map[string]bool), entries: make(map[Target]*entry), flights: make(map[Target]*flight), root: root, cancel: cancel, sem: make(chan struct{}, cfg.MaxConcurrentProbes), done: make(chan struct{})}
	for _, id := range cfg.Candidates {
		c.ids[id] = true
	}
	return c, nil
}

// Select chooses a strategy for a future connection. It never replays traffic or
// changes an existing connection. Shared work outlives a single canceled waiter.
func (c *Controller) Select(ctx context.Context, t Target, o SelectOptions) (Selection, error) {
	if err := ctx.Err(); err != nil {
		return Selection{}, err
	}
	t, err := normalize(t)
	if err != nil {
		return Selection{}, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return Selection{}, ErrClosed
	}
	if o.Manual != "" {
		c.mu.Unlock()
		if !c.ids[o.Manual] {
			return Selection{}, fmtError("unknown manual strategy")
		}
		return Selection{Strategy: o.Manual, Source: "manual"}, nil
	}
	e, err := c.entryLocked(t)
	if err != nil {
		c.mu.Unlock()
		return Selection{}, err
	}
	now := c.cfg.Now()
	fresh := e.selected.Strategy != "" && now.Before(e.selected.ExpiresAt)
	stale := e.selected.Strategy != "" && c.cfg.StaleTTL > 0 && now.Before(e.selected.ExpiresAt.Add(c.cfg.StaleTTL))
	if !o.Refresh && (fresh || stale) {
		s := e.selected
		s.Source = "cache"
		s.CacheHit = true
		s.Stale = !fresh
		s.ProbeAttempts = 0
		s.DiscoveryDuration = 0
		if !fresh {
			s.Source = "stale"
		}
		if c.cfg.BackgroundRevalidate && !c.cfg.DisableDiscovery && !now.Before(e.nextBackground) && (!fresh || !now.Before(s.VerifiedAt.Add(c.cfg.RevalidateAfter))) {
			if c.flights[t] == nil && c.background < c.cfg.BackgroundConcurrency && len(c.flights) < c.cfg.MaxDiscoveries {
				c.startLocked(t, e, true, false)
			}
		}
		c.mu.Unlock()
		return s, ctx.Err()
	}
	if c.cfg.DisableDiscovery {
		c.mu.Unlock()
		return Selection{}, ErrDiscoveryDisabled
	}
	f := c.flights[t]
	if f == nil {
		if !o.Refresh && now.Before(e.negativeUntil) {
			c.mu.Unlock()
			return Selection{}, ErrNegativeCached
		}
		if len(c.flights) >= c.cfg.MaxDiscoveries {
			c.mu.Unlock()
			return Selection{}, ErrCapacity
		}
		f = c.startLocked(t, e, false, o.Refresh)
	}
	f.waiters++
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-f.done:
		err = f.err
	}
	c.mu.Lock()
	f.waiters--
	if f.waiters == 0 && !f.background {
		f.cancel()
	}
	c.mu.Unlock()
	if ctx.Err() != nil {
		return Selection{}, ctx.Err()
	}
	if err != nil {
		return Selection{}, err
	}
	return f.result, nil
}

func (c *Controller) entryLocked(t Target) (*entry, error) {
	if e := c.entries[t]; e != nil {
		c.clock++
		e.used = c.clock
		return e, nil
	}
	if len(c.entries) >= c.cfg.MaxEntries {
		var victim Target
		var oldest *entry
		for key, e := range c.entries {
			if c.flights[key] == nil && (oldest == nil || e.used < oldest.used) {
				victim = key
				oldest = e
			}
		}
		if oldest == nil {
			return nil, ErrCapacity
		}
		delete(c.entries, victim)
	}
	c.clock++
	e := &entry{stats: make(map[string]*CandidateStats), used: c.clock}
	c.entries[t] = e
	return e, nil
}

// startLocked registers all goroutine ownership before Close can begin waiting.
func (c *Controller) startLocked(t Target, e *entry, bg, refresh bool) *flight {
	ctx, cancel := context.WithTimeout(c.root, c.cfg.DiscoveryTimeout)
	f := &flight{ctx: ctx, cancel: cancel, done: make(chan struct{}), entry: e, generation: e.generation, background: bg, refresh: refresh}
	c.flights[t] = f
	if bg {
		c.background++
	}
	c.wg.Add(1)
	go c.discover(t, f)
	return f
}

// Invalidate reports an observed failure. The caller chooses whether the failed
// operation can be retried; this package has no application payload to replay.
func (c *Controller) Invalidate(t Target, strategy, code string) error {
	t, err := normalize(t)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClosed
	}
	if !c.ids[strategy] {
		return fmtError("unknown strategy")
	}
	e := c.entries[t]
	if e == nil {
		return nil
	}
	e.generation++
	if f := c.flights[t]; f != nil {
		f.cancel()
	}
	if e.selected.Strategy == strategy {
		e.selected = Selection{}
	}
	e.negativeUntil = time.Time{}
	e.negativeReason = ""
	e.nextBackground = time.Time{}
	c.recordLocked(t, e, strategy, Proof{}, "feedback", code, 0, 0)
	return nil
}

// Close cancels work. A Prober must honor its context: Go cannot kill a blocked
// callback. Such a callback retains its global slot until it actually returns.
func (c *Controller) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		c.cancel()
		go func() { c.wg.Wait(); close(c.done) }()
	}
	return nil
}

func (c *Controller) Shutdown(ctx context.Context) error {
	c.Close()
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
