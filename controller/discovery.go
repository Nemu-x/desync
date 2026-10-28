package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
)

func fmtError(s string) error { return fmt.Errorf("controller: %s", s) }

var errInsufficientProof = errors.New("insufficient proof")

type probeResult struct {
	id       string
	proof    Proof
	duration time.Duration
	queue    time.Duration
	err      error
}

func (c *Controller) rankedLocked(e *entry, refresh bool) []string {
	now := c.cfg.Now()
	ids := make([]string, 0, len(c.cfg.Candidates))
	for _, id := range c.cfg.Candidates {
		s := e.stats[id]
		if refresh || s == nil || !now.Before(s.NegativeUntil) {
			ids = append(ids, id)
		}
	}
	sort.SliceStable(ids, func(i, j int) bool {
		a, b := e.stats[ids[i]], e.stats[ids[j]]
		if ids[i] == e.selected.Strategy {
			return true
		}
		if ids[j] == e.selected.Strategy {
			return false
		}
		score := func(s *CandidateStats) float64 {
			if s == nil {
				return .5
			}
			return (float64(s.Successes) + 1) / (float64(s.Successes) + float64(s.Failures) + 2)
		}
		sa, sb := score(a), score(b)
		if sa != sb {
			return sa > sb
		}
		if a != nil && b != nil && a.EWMA > 0 && b.EWMA > 0 && a.EWMA != b.EWMA {
			return a.EWMA < b.EWMA
		}
		return false
	})
	if len(ids) > c.cfg.MaxAttempts {
		ids = ids[:c.cfg.MaxAttempts]
	}
	return ids
}

func (c *Controller) discover(t Target, f *flight) {
	defer c.wg.Done()
	defer f.cancel()
	start := time.Now()
	c.mu.Lock()
	ids := c.rankedLocked(f.entry, f.refresh)
	lkg := f.entry.selected.Strategy
	c.mu.Unlock()
	results := make(chan probeResult, c.cfg.MaxParallelProbes)
	next, active, attempts := 0, 0, 0
	parallel := c.cfg.MaxParallelProbes
	if f.background {
		parallel = 1
	}
	// Confirm last-known-good alone before widening a failed revalidation.
	if len(ids) > 0 && ids[0] == lkg {
		parallel = 1
	}
	var chosen Selection
	var finalErr error
	for {
		for next < len(ids) && active < parallel {
			c.mu.Lock()
			if c.closed || f.ctx.Err() != nil {
				c.mu.Unlock()
				break
			}
			id := ids[next]
			next++
			active++
			attempts++
			c.wg.Add(1)
			go c.probe(t, f, id, results)
			c.mu.Unlock()
		}
		if active == 0 {
			finalErr = ErrNoStrategy
			break
		}
		select {
		case <-f.ctx.Done():
			finalErr = f.ctx.Err()
		case r := <-results:
			active--
			parallel = c.cfg.MaxParallelProbes
			if f.background {
				parallel = 1
			}
			if r.err == nil {
				chosen = Selection{Strategy: r.id, Source: "probe", Level: r.proof.Level, ProbeDuration: r.duration, QueueDuration: r.queue}
				break
			}
			continue
		}
		break
	}
	c.mu.Lock()
	if c.closed {
		finalErr = ErrClosed
	} else if f.entry.generation != f.generation {
		finalErr = ErrInvalidated
	} else if f.ctx.Err() != nil {
		finalErr = f.ctx.Err()
	}
	now := c.cfg.Now()
	if finalErr == nil && chosen.Strategy != "" {
		chosen.VerifiedAt = now
		chosen.ExpiresAt = now.Add(c.cfg.CacheTTL)
		chosen.DiscoveryDuration = time.Since(start)
		chosen.ProbeAttempts = attempts
		f.entry.selected = chosen
		f.entry.negativeUntil = time.Time{}
		f.entry.negativeReason = ""
	} else if (errors.Is(finalErr, ErrNoStrategy) || errors.Is(finalErr, context.DeadlineExceeded)) && f.entry.generation == f.generation {
		// A failed refresh must not erase a still-valid last-known-good result.
		f.entry.negativeUntil = now.Add(c.cfg.NegativeTTL)
		f.entry.negativeReason = "no_verified_strategy"
		if errors.Is(finalErr, context.DeadlineExceeded) {
			f.entry.negativeReason = "discovery_timeout"
		}
	}
	f.entry.nextBackground = now.Add(c.cfg.NegativeTTL)
	f.result = chosen
	f.err = finalErr
	if c.flights[t] == f {
		delete(c.flights, t)
	}
	if f.background {
		c.background--
	}
	close(f.done)
	c.mu.Unlock()
}

func (c *Controller) probe(t Target, f *flight, id string, out chan<- probeResult) {
	defer c.wg.Done()
	ctx, cancel := context.WithTimeout(f.ctx, c.cfg.ProbeTimeout)
	defer cancel()
	r := probeResult{id: id}
	start := time.Now()
	select {
	case c.sem <- struct{}{}:
		r.queue = time.Since(start)
		// Slot spans the actual callback lifetime, even if it ignores context.
		if ctx.Err() == nil {
			probeStart := time.Now()
			r.proof, r.err = c.prober.Probe(ctx, t, id)
			r.duration = time.Since(probeStart)
		} else {
			r.err = ctx.Err()
		}
		<-c.sem
	case <-ctx.Done():
		r.queue = time.Since(start)
		r.err = ctx.Err()
	}
	if ctx.Err() != nil {
		r.err = ctx.Err()
	}
	if r.err == nil && (r.proof.Level < t.Required || r.proof.Level > Application) {
		r.err = errInsufficientProof
	}
	code, outcome := "verified", "success"
	if r.err != nil {
		outcome = "failure"
		code = "probe_failed"
		if f.ctx.Err() != nil {
			outcome = "canceled"
			code = "canceled"
		} else if errors.Is(r.err, context.DeadlineExceeded) {
			code = "probe_timeout"
		} else if errors.Is(r.err, errInsufficientProof) {
			code = "insufficient_proof"
		}
	} else if token(r.proof.Code, 64) {
		code = r.proof.Code
	}
	c.mu.Lock()
	if !c.closed && c.entries[t] == f.entry && f.entry.generation == f.generation {
		c.recordLocked(t, f.entry, id, r.proof, outcome, code, r.duration, r.queue)
	}
	c.mu.Unlock()
	out <- r
}
