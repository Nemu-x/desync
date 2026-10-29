package main

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// target is one host to measure.
type target struct {
	Host string
	Port int
}

func (t target) String() string {
	if t.Port == 443 {
		return t.Host
	}
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// runConfig bounds a measurement run.
type runConfig struct {
	Repeat      int           // attempts per target × strategy pair
	Concurrency int           // attempts in flight at once
	Budget      time.Duration // whole run, DNS included; 0 means no limit
}

// pairResult holds the attempts of one target × strategy pair. A nil entry
// in Attempts was not run (DNS failed or the budget ran out).
type pairResult struct {
	Attempts []*attemptResult
}

// runResult is everything a run measured, indexed like the inputs.
type runResult struct {
	DNS        []dnsResult
	Address    []net.IP // the address measured per target, nil when DNS failed
	Pairs      [][]pairResult
	Elapsed    time.Duration
	Incomplete bool // the budget ran out or ctx was canceled before every attempt ran
}

// progressEvent is reported after every attempt.
type progressEvent struct {
	Done, Total int
	Target      target
	Preset      preset
	Result      *attemptResult // nil when the attempt was not run
}

// run measures every preset against every target. Attempts are interleaved
// (repetition, then preset, then target) so one server never sees a burst
// and repetitions of a pair are spread over the run.
func run(ctx context.Context, p *prober, targets []target, presets []preset, cfg runConfig, progress func(progressEvent)) runResult {
	start := time.Now()
	if cfg.Repeat < 1 {
		cfg.Repeat = 1
	}
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	if cfg.Budget > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Budget)
		defer cancel()
	}
	res := runResult{
		DNS:     make([]dnsResult, len(targets)),
		Address: make([]net.IP, len(targets)),
		Pairs:   make([][]pairResult, len(targets)),
	}
	for i := range res.Pairs {
		res.Pairs[i] = make([]pairResult, len(presets))
		for j := range res.Pairs[i] {
			res.Pairs[i][j].Attempts = make([]*attemptResult, cfg.Repeat)
		}
	}

	// Resolve every name first, with the same concurrency bound.
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t target) {
			defer func() { <-sem; wg.Done() }()
			res.DNS[i] = p.resolve(ctx, t.Host)
			if res.DNS[i].Err == nil {
				res.Address[i] = pickAddress(res.DNS[i].IPs)
			}
		}(i, t)
	}
	wg.Wait()

	type job struct{ t, s, rep int }
	var jobs []job
	for rep := 0; rep < cfg.Repeat; rep++ {
		for s := range presets {
			for t := range targets {
				jobs = append(jobs, job{t, s, rep})
			}
		}
	}
	var mu sync.Mutex
	done := 0
	report := func(j job, r *attemptResult) {
		mu.Lock()
		defer mu.Unlock()
		res.Pairs[j.t][j.s].Attempts[j.rep] = r
		done++
		if r == nil && res.Address[j.t] != nil {
			res.Incomplete = true
		}
		if progress != nil {
			progress(progressEvent{Done: done, Total: len(jobs), Target: targets[j.t], Preset: presets[j.s], Result: r})
		}
	}
	queue := make(chan job)
	for w := 0; w < cfg.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range queue {
				ip := res.Address[j.t]
				if ip == nil || ctx.Err() != nil {
					report(j, nil)
					continue
				}
				r := p.attempt(ctx, targets[j.t].Host, ip, targets[j.t].Port, presets[j.s].Opts)
				if !r.ok() && ctx.Err() != nil {
					// The budget, not the network, ended this attempt.
					report(j, nil)
					continue
				}
				report(j, &r)
			}
		}()
	}
	for _, j := range jobs {
		queue <- j
	}
	close(queue)
	wg.Wait()
	res.Elapsed = time.Since(start)
	return res
}

// Outcomes of a pair across its repetitions.
const (
	outcomeWorks  = "works"
	outcomeFlaky  = "flaky"
	outcomeFails  = "fails"
	outcomeNotRun = "not-run"
)

// summary aggregates the attempts of one pair.
type summary struct {
	Outcome string
	OK, Run int
	// Class is the most frequent error class among failed attempts.
	Class string
}

func summarize(pr pairResult) summary {
	var s summary
	counts := map[string]int{}
	var order []string
	for _, a := range pr.Attempts {
		if a == nil {
			continue
		}
		s.Run++
		if a.ok() {
			s.OK++
			continue
		}
		if counts[a.Class] == 0 {
			order = append(order, a.Class)
		}
		counts[a.Class]++
	}
	for _, c := range order {
		if counts[c] > counts[s.Class] {
			s.Class = c
		}
	}
	switch {
	case s.Run == 0:
		s.Outcome = outcomeNotRun
	case s.OK == s.Run:
		s.Outcome = outcomeWorks
	case s.OK > 0:
		s.Outcome = outcomeFlaky
	default:
		s.Outcome = outcomeFails
	}
	return s
}

// parseTargets reads host or host:port entries separated by commas,
// whitespace or newlines; '#' starts a comment.
func parseTargets(text string, defaultPort int) ([]target, error) {
	var out []target
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, f := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\r' }) {
			t, err := parseTarget(f, defaultPort)
			if err != nil {
				return nil, err
			}
			if !seen[t.String()] {
				seen[t.String()] = true
				out = append(out, t)
			}
		}
	}
	return out, nil
}

func parseTarget(s string, defaultPort int) (target, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	s = strings.TrimRight(s, "/")
	host, port := s, defaultPort
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return target{}, &targetError{s, "bad port"}
		}
		host, port = h, n
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/@?#[] ") {
		return target{}, &targetError{s, "not a host name"}
	}
	return target{Host: host, Port: port}, nil
}

type targetError struct{ entry, why string }

func (e *targetError) Error() string { return "target " + strconv.Quote(e.entry) + ": " + e.why }
