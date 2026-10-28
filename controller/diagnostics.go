package controller

import "time"

type CandidateStats struct {
	Strategy                      string
	Successes, Failures, Canceled uint64
	LastVerified                  time.Time
	LastDuration, EWMA            time.Duration
	NegativeUntil                 time.Time
	LastCode                      string
}

type Attempt struct {
	At                      time.Time
	Target                  Target
	Strategy, Outcome, Code string
	Level                   Verification
	Duration, QueueDuration time.Duration
}

type Status struct {
	Closed                             bool
	Entries, Discoveries, ActiveProbes int
	Attempts                           []Attempt
}

func increment(p *uint64) {
	if *p < ^uint64(0) {
		*p++
	}
}

func (c *Controller) recordLocked(t Target, e *entry, id string, p Proof, outcome, code string, d, queue time.Duration) {
	if !token(code, 64) {
		code = "probe_failed"
	}
	s := e.stats[id]
	if s == nil {
		s = &CandidateStats{Strategy: id}
		e.stats[id] = s
	}
	now := c.cfg.Now()
	s.LastCode = code
	s.LastDuration = d
	switch outcome {
	case "success":
		increment(&s.Successes)
		s.LastVerified = now
		s.NegativeUntil = time.Time{}
		if s.EWMA == 0 {
			s.EWMA = d
		} else {
			s.EWMA = s.EWMA - s.EWMA/4 + d/4
		}
	case "failure", "feedback":
		increment(&s.Failures)
		s.NegativeUntil = now.Add(c.cfg.NegativeTTL)
	case "canceled":
		increment(&s.Canceled)
	}
	a := Attempt{At: now, Target: t, Strategy: id, Outcome: outcome, Code: code, Level: p.Level, Duration: d, QueueDuration: queue}
	if len(c.history) == c.cfg.HistoryLimit {
		copy(c.history, c.history[1:])
		c.history[len(c.history)-1] = a
	} else {
		c.history = append(c.history, a)
	}
}

// Status contains bounded diagnostics with stable codes, never raw error text.
func (c *Controller) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Status{Closed: c.closed, Entries: len(c.entries), Discoveries: len(c.flights), ActiveProbes: len(c.sem), Attempts: append([]Attempt(nil), c.history...)}
}
