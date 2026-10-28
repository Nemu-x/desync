package controller

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var target = Target{Network: "test-network", Host: "example.test", Port: 443, ProbeID: "test-response-v1"}

func config() Config {
	return Config{Candidates: []string{"a", "b", "c"}, PolicyVersion: "test-v1", ProbeTimeout: time.Second, DiscoveryTimeout: 2 * time.Second, MaxParallelProbes: 1}
}
func controller(t *testing.T, cfg Config, p Prober) *Controller {
	t.Helper()
	c, err := New(cfg, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := c.Shutdown(ctx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	})
	return c
}
func choose(t *testing.T, c *Controller, tar Target, o SelectOptions) Selection {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, err := c.Select(ctx, tar, o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
		var v T
		return v
	}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (k *clock) now() time.Time      { k.mu.Lock(); defer k.mu.Unlock(); return k.t }
func (k *clock) add(d time.Duration) { k.mu.Lock(); k.t = k.t.Add(d); k.mu.Unlock() }
func newClock() *clock               { return &clock{t: time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)} }

func TestControllerProofCacheAndTarget(t *testing.T) {
	var calls atomic.Int32
	k := newClock()
	cfg := config()
	cfg.Now = k.now
	cfg.CacheTTL = time.Minute
	c := controller(t, cfg, ProbeFunc(func(_ context.Context, _ Target, id string) (Proof, error) {
		calls.Add(1)
		if id == "a" {
			return Proof{Level: TCP}, nil
		}
		return Proof{Level: Application, Code: "expected_response"}, nil
	}))
	s := choose(t, c, target, SelectOptions{})
	if s.Strategy != "b" || s.ProbeAttempts != 2 || s.Level != Application {
		t.Fatalf("%+v", s)
	}
	alias := target
	alias.Host = " EXAMPLE.TEST. "
	s = choose(t, c, alias, SelectOptions{})
	if !s.CacheHit || s.ProbeAttempts != 0 || calls.Load() != 2 {
		t.Fatalf("cache %+v, calls %d", s, calls.Load())
	}
	k.add(2 * time.Minute)
	s = choose(t, c, target, SelectOptions{})
	if s.Strategy != "b" || calls.Load() != 3 {
		t.Fatalf("LKG first %+v calls %d", s, calls.Load())
	}
	other := target
	other.Network = "different-network"
	choose(t, c, other, SelectOptions{})
	if calls.Load() != 5 {
		t.Fatal("network did not isolate cache")
	}
	if got := c.Status().Attempts[0].Code; got != "insufficient_proof" {
		t.Fatal(got)
	}
}

func TestControllerValidationManualAndDisabled(t *testing.T) {
	for _, mutate := range []func(*Config){func(c *Config) { c.Candidates = []string{"a", "a"} }, func(c *Config) { c.CacheTTL = -1 }, func(c *Config) { c.PolicyVersion = "" }, func(c *Config) { c.MaxParallelProbes = -1 }} {
		cfg := config()
		mutate(&cfg)
		if c, err := New(cfg, nil); err == nil {
			c.Close()
			t.Fatal("accepted invalid config")
		}
	}
	cfg := config()
	cfg.DisableDiscovery = true
	c := controller(t, cfg, nil)
	s := choose(t, c, target, SelectOptions{Manual: "a"})
	if s.Source != "manual" || s.Level != Unknown || !s.VerifiedAt.IsZero() {
		t.Fatalf("%+v", s)
	}
	if _, err := c.Select(context.Background(), target, SelectOptions{}); !errors.Is(err, ErrDiscoveryDisabled) {
		t.Fatal(err)
	}
	if _, err := c.Select(context.Background(), target, SelectOptions{Manual: "bad"}); err == nil {
		t.Fatal("unknown manual")
	}
	for _, bad := range []Target{{Network: "n", Host: "https://example.test", Port: 443, ProbeID: "p"}, {Network: "n", Host: "example.test", Port: 443, ProbeID: "p", Required: TCP}, {Network: "n", Host: "foo\nbar", Port: 443, ProbeID: "p"}, {Host: "example.test", Port: 443, ProbeID: "p"}} {
		if _, err := c.Select(context.Background(), bad, SelectOptions{Manual: "a"}); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Select(ctx, target, SelectOptions{Manual: "a"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ip := target
	ip.Host = "::ffff:192.0.2.1"
	n, err := normalize(ip)
	if err != nil || n.Host != "192.0.2.1" {
		t.Fatalf("%+v %v", n, err)
	}
}

func TestControllerSingleflightAndWaiterCancellation(t *testing.T) {
	started, release := make(chan struct{}, 1), make(chan struct{})
	var calls atomic.Int32
	c := controller(t, config(), ProbeFunc(func(ctx context.Context, _ Target, _ string) (Proof, error) {
		calls.Add(1)
		started <- struct{}{}
		select {
		case <-release:
			return Proof{Level: Application}, nil
		case <-ctx.Done():
			return Proof{}, ctx.Err()
		}
	}))
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := c.Select(ctx, target, SelectOptions{}); first <- err }()
	await(t, started)
	const n = 32
	out := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { _, err := c.Select(context.Background(), target, SelectOptions{}); out <- err }()
	}
	// Synchronize on registered waiters, without timing assumptions or sleeps.
	waitFor(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.flights[mustTarget(t, target)].waiters == n+1 })
	cancel()
	if err := await(t, first); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	for i := 0; i < n; i++ {
		if err := await(t, out); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal(calls.Load())
	}
}

func mustTarget(t *testing.T, x Target) Target {
	t.Helper()
	v, err := normalize(x)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for !f() {
		select {
		case <-deadline.C:
			t.Fatal("condition timed out")
		default:
		}
		runtime.Gosched()
	}
}

func TestControllerAllWaitersCancelAndClose(t *testing.T) {
	started, canceled := make(chan struct{}, 1), make(chan struct{}, 1)
	c := controller(t, config(), ProbeFunc(func(ctx context.Context, _ Target, _ string) (Proof, error) {
		started <- struct{}{}
		<-ctx.Done()
		canceled <- struct{}{}
		return Proof{}, ctx.Err()
	}))
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan error, 1)
	go func() { _, err := c.Select(ctx, target, SelectOptions{}); out <- err }()
	await(t, started)
	cancel()
	await(t, out)
	await(t, canceled)
	waitFor(t, func() bool { return c.Status().Discoveries == 0 })
	if len(c.Export().Entries) != 1 || c.Export().Entries[0].Selection.Strategy != "" {
		t.Fatal("canceled proof cached")
	}
	c.Close()
	if _, err := c.Select(context.Background(), target, SelectOptions{Manual: "a"}); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestControllerBudgetsNegativeAndRanking(t *testing.T) {
	k := newClock()
	cfg := config()
	cfg.Now = k.now
	cfg.MaxAttempts = 2
	cfg.NegativeTTL = time.Minute
	var calls atomic.Int32
	c := controller(t, cfg, ProbeFunc(func(context.Context, Target, string) (Proof, error) {
		calls.Add(1)
		return Proof{}, errors.New("private error text")
	}))
	if _, err := c.Select(context.Background(), target, SelectOptions{}); !errors.Is(err, ErrNoStrategy) {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal(calls.Load())
	}
	if _, err := c.Select(context.Background(), target, SelectOptions{}); !errors.Is(err, ErrNegativeCached) {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("negative cache probed")
	}
	k.add(2 * time.Minute)
	if _, err := c.Select(context.Background(), target, SelectOptions{}); !errors.Is(err, ErrNoStrategy) {
		t.Fatal(err)
	}
	// Previously untried candidate c ranks before known failures a/b.
	h := c.Status().Attempts
	if h[2].Strategy != "c" {
		t.Fatalf("ranking: %+v", h)
	}
	for _, a := range h {
		if a.Code == "private error text" {
			t.Fatal("raw error leaked")
		}
	}
	before := calls.Load()
	c.Select(context.Background(), target, SelectOptions{Refresh: true})
	if calls.Load()-before != 2 {
		t.Fatal("refresh exceeded/lost budget")
	}
}

func TestControllerParallelBoundsAndLoserCancellation(t *testing.T) {
	cfg := config()
	cfg.MaxParallelProbes = 3
	cfg.MaxConcurrentProbes = 2
	started := make(chan string, 10)
	release := make(chan struct{})
	var active, peak atomic.Int32
	c := controller(t, cfg, ProbeFunc(func(ctx context.Context, _ Target, id string) (Proof, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		started <- id
		select {
		case <-release:
			return Proof{Level: Application}, nil
		case <-ctx.Done():
			return Proof{}, ctx.Err()
		}
	}))
	out := make(chan error, 2)
	for i := 0; i < 2; i++ {
		x := target
		x.Host = fmt.Sprintf("%d.test", i)
		go func() { _, err := c.Select(context.Background(), x, SelectOptions{}); out <- err }()
	}
	await(t, started)
	await(t, started)
	if peak.Load() != 2 {
		t.Fatal(peak.Load())
	}
	close(release)
	for i := 0; i < 2; i++ {
		if err := await(t, out); err != nil {
			t.Fatal(err)
		}
	}
	if peak.Load() > 2 {
		t.Fatal("global bound exceeded")
	}
}

func TestControllerDeadlinesAndNoncooperativeProbe(t *testing.T) {
	cfg := config()
	cfg.MaxConcurrentProbes = 1
	cfg.DiscoveryTimeout = 40 * time.Millisecond
	cfg.ProbeTimeout = 15 * time.Millisecond
	started, release := make(chan struct{}, 1), make(chan struct{})
	var calls atomic.Int32
	c := controller(t, cfg, ProbeFunc(func(context.Context, Target, string) (Proof, error) {
		calls.Add(1)
		started <- struct{}{}
		<-release
		return Proof{Level: Application}, nil
	}))
	defer close(release)
	out := make(chan error, 1)
	go func() { _, err := c.Select(context.Background(), target, SelectOptions{}); out <- err }()
	await(t, started)
	if err := await(t, out); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if _, err := c.Select(context.Background(), target, SelectOptions{}); !errors.Is(err, ErrNegativeCached) {
		t.Fatal("discovery timeout not cached", err)
	}
	x := target
	x.Host = "other.test"
	c.Select(context.Background(), x, SelectOptions{})
	if calls.Load() != 1 || c.Status().ActiveProbes != 1 {
		t.Fatal("noncooperative callback released slot")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := c.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestControllerInvalidationAndCapacity(t *testing.T) {
	cfg := config()
	cfg.MaxEntries = 1
	cfg.MaxDiscoveries = 1
	started, release := make(chan struct{}, 1), make(chan struct{})
	c := controller(t, cfg, ProbeFunc(func(context.Context, Target, string) (Proof, error) {
		started <- struct{}{}
		<-release
		return Proof{Level: Application}, nil
	}))
	out := make(chan error, 1)
	go func() { _, err := c.Select(context.Background(), target, SelectOptions{}); out <- err }()
	await(t, started)
	x := target
	x.Host = "other.test"
	if _, err := c.Select(context.Background(), x, SelectOptions{}); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if err := c.Restore(c.Export()); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if err := c.Invalidate(target, "a", "application_failed"); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := await(t, out); !errors.Is(err, ErrInvalidated) {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return c.Status().ActiveProbes == 0 })
	for _, e := range c.Export().Entries {
		if e.Selection.Strategy != "" {
			t.Fatal("late invalidated result cached")
		}
	}
}
