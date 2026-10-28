package controller

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestControllerBackgroundStaleAndLastKnownGood(t *testing.T) {
	k := newClock()
	cfg := config()
	cfg.Now = k.now
	cfg.CacheTTL = time.Minute
	cfg.StaleTTL = time.Minute
	cfg.BackgroundRevalidate = true
	cfg.RevalidateAfter = 30 * time.Second
	var fail atomic.Bool
	events := make(chan struct{}, 16)
	release := make(chan struct{})
	var calls atomic.Int32
	c := controller(t, cfg, ProbeFunc(func(ctx context.Context, _ Target, _ string) (Proof, error) {
		calls.Add(1)
		if fail.Load() {
			events <- struct{}{}
			select {
			case <-release:
				return Proof{}, errors.New("unavailable")
			case <-ctx.Done():
				return Proof{}, ctx.Err()
			}
		}
		return Proof{Level: Application}, nil
	}))
	choose(t, c, target, SelectOptions{})
	fail.Store(true)
	k.add(35 * time.Second)
	s := choose(t, c, target, SelectOptions{})
	if !s.CacheHit || s.Stale {
		t.Fatalf("%+v", s)
	}
	await(t, events)
	// A fresh hit returns while background validation is deliberately blocked.
	choose(t, c, target, SelectOptions{})
	if calls.Load() != 2 {
		t.Fatal("duplicate background probe")
	}
	close(release)
	waitFor(t, func() bool { return c.Status().Discoveries == 0 })
	s = choose(t, c, target, SelectOptions{})
	if s.Strategy != "a" || s.Stale {
		t.Fatal("failed refresh erased valid result")
	}
	k.add(30 * time.Second)
	s = choose(t, c, target, SelectOptions{})
	if !s.Stale || s.Source != "stale" {
		t.Fatalf("%+v", s)
	}
	waitFor(t, func() bool { return c.Status().Discoveries == 0 })
	k.add(2 * time.Minute)
	if _, err := c.Select(context.Background(), target, SelectOptions{}); err == nil {
		t.Fatal("stale cached indefinitely")
	}
}

func TestControllerNoImplicitBackgroundAndLRU(t *testing.T) {
	k := newClock()
	cfg := config()
	cfg.Now = k.now
	cfg.MaxEntries = 2
	var calls atomic.Int32
	c := controller(t, cfg, ProbeFunc(func(context.Context, Target, string) (Proof, error) {
		calls.Add(1)
		return Proof{Level: Application}, nil
	}))
	choose(t, c, target, SelectOptions{})
	second := target
	second.Host = "second.test"
	choose(t, c, second, SelectOptions{})
	k.add(20 * time.Minute)
	choose(t, c, target, SelectOptions{})
	third := target
	third.Host = "third.test"
	choose(t, c, third, SelectOptions{})
	if calls.Load() != 3 || c.Status().Entries != 2 {
		t.Fatal("unexpected probes/entries")
	}
	for _, x := range c.Export().Entries {
		if x.Target.Host == second.Host {
			t.Fatal("LRU entry not evicted")
		}
	}
}

func TestControllerSnapshotValidationAndDisabledCache(t *testing.T) {
	k := newClock()
	cfg := config()
	cfg.Now = k.now
	cfg.CacheTTL = time.Minute
	cfg.NegativeTTL = time.Second
	c := controller(t, cfg, ProbeFunc(func(context.Context, Target, string) (Proof, error) { return Proof{Level: Application}, nil }))
	choose(t, c, target, SelectOptions{})
	raw, err := json.Marshal(c.Export())
	if err != nil {
		t.Fatal(err)
	}
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	cfg.DisableDiscovery = true
	restored := controller(t, cfg, nil)
	if err := restored.Restore(s); err != nil {
		t.Fatal(err)
	}
	if got := choose(t, restored, target, SelectOptions{}); !got.CacheHit || got.Level != Application {
		t.Fatalf("%+v", got)
	}
	for _, mutate := range []func(*Snapshot){
		func(s *Snapshot) { s.Version++ }, func(s *Snapshot) { s.PolicyVersion = "other" },
		func(s *Snapshot) { s.Entries[0].Selection.Level = TCP }, func(s *Snapshot) { s.Entries[0].Selection.Strategy = "unknown" },
		func(s *Snapshot) { s.Entries[0].Selection.VerifiedAt = k.now().Add(time.Hour) },
		func(s *Snapshot) { s.Entries = append(s.Entries, s.Entries[0]) },
	} {
		var bad Snapshot
		json.Unmarshal(raw, &bad)
		mutate(&bad)
		if err := restored.Restore(bad); err == nil {
			t.Fatal("accepted invalid snapshot")
		}
		if !choose(t, restored, target, SelectOptions{}).CacheHit {
			t.Fatal("failed restore mutated state")
		}
	}
	// A snapshot cannot extend the current policy's TTL or cooldown.
	s.Entries[0].Selection.ExpiresAt = k.now().Add(24 * time.Hour)
	s.Entries[0].Candidates[0].NegativeUntil = k.now().Add(24 * time.Hour)
	if err := restored.Restore(s); err != nil {
		t.Fatal(err)
	}
	got := restored.Export().Entries[0]
	if got.Selection.ExpiresAt.After(k.now().Add(cfg.CacheTTL)) {
		t.Fatal("unbounded TTL restored")
	}
	if got.Candidates[0].NegativeUntil.After(k.now().Add(cfg.NegativeTTL)) {
		t.Fatal("unbounded cooldown restored")
	}
}

func TestControllerTLSOptInAndFiniteTimeout(t *testing.T) {
	cfg := config()
	cfg.ProbeTimeout = 15 * time.Millisecond
	cfg.MaxAttempts = 2
	var calls atomic.Int32
	c := controller(t, cfg, ProbeFunc(func(ctx context.Context, _ Target, id string) (Proof, error) {
		calls.Add(1)
		if id == "a" {
			<-ctx.Done()
			return Proof{}, ctx.Err()
		}
		return Proof{Level: TLS}, nil
	}))
	tlsTarget := target
	tlsTarget.Required = TLS
	s := choose(t, c, tlsTarget, SelectOptions{})
	if s.Strategy != "b" || s.Level != TLS {
		t.Fatalf("%+v", s)
	}
	if _, err := c.Select(context.Background(), target, SelectOptions{}); !errors.Is(err, ErrNoStrategy) {
		t.Fatal("TLS-only proof accepted for application", err)
	}
	if calls.Load() != 4 {
		t.Fatal(calls.Load())
	}
	if c.Status().Attempts[0].Code != "probe_timeout" {
		t.Fatal(c.Status())
	}
}

func TestControllerBoundedHistoryAndCatalogCopy(t *testing.T) {
	cfg := config()
	cfg.HistoryLimit = 2
	c := controller(t, cfg, ProbeFunc(func(context.Context, Target, string) (Proof, error) { return Proof{Level: Application}, nil }))
	cfg.Candidates[0] = "mutated"
	for i := 0; i < 5; i++ {
		if choose(t, c, target, SelectOptions{Refresh: true}).Strategy != "a" {
			t.Fatal("catalog not cloned")
		}
	}
	status := c.Status()
	if len(status.Attempts) != 2 {
		t.Fatal(len(status.Attempts))
	}
	status.Attempts[0].Code = "mutated"
	if c.Status().Attempts[0].Code == "mutated" {
		t.Fatal("diagnostics not cloned")
	}
}
