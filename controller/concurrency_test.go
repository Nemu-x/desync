package controller

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestControllerWinningProbeCancelsLoser(t *testing.T) {
	cfg := config()
	cfg.MaxParallelProbes = 2
	loserStarted, loserCanceled := make(chan struct{}), make(chan struct{})
	c := controller(t, cfg, ProbeFunc(func(ctx context.Context, _ Target, id string) (Proof, error) {
		if id == "a" {
			select {
			case <-loserStarted:
				return Proof{Level: Application}, nil
			case <-ctx.Done():
				return Proof{}, ctx.Err()
			}
		}
		close(loserStarted)
		<-ctx.Done()
		close(loserCanceled)
		return Proof{}, ctx.Err()
	}))
	if got := choose(t, c, target, SelectOptions{}); got.Strategy != "a" {
		t.Fatal(got)
	}
	await(t, loserCanceled)
	waitFor(t, func() bool { return len(c.Status().Attempts) == 2 })
	for _, s := range c.Export().Entries[0].Candidates {
		if s.Strategy == "b" && (s.Canceled != 1 || s.Failures != 0) {
			t.Fatalf("loser penalized: %+v", s)
		}
	}
}

func TestControllerDiscoveryCapacity(t *testing.T) {
	cfg := config()
	cfg.MaxDiscoveries = 1
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	c := controller(t, cfg, ProbeFunc(func(ctx context.Context, _ Target, _ string) (Proof, error) {
		started <- struct{}{}
		select {
		case <-release:
			return Proof{Level: Application}, nil
		case <-ctx.Done():
			return Proof{}, ctx.Err()
		}
	}))
	out := make(chan error, 1)
	go func() { _, err := c.Select(context.Background(), target, SelectOptions{}); out <- err }()
	await(t, started)
	x := target
	x.Host = "other.test"
	if _, err := c.Select(context.Background(), x, SelectOptions{}); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	close(release)
	if err := await(t, out); err != nil {
		t.Fatal(err)
	}
}

func TestControllerCloseCannotPublishLateProof(t *testing.T) {
	started, release := make(chan struct{}, 1), make(chan struct{})
	c := controller(t, config(), ProbeFunc(func(context.Context, Target, string) (Proof, error) {
		started <- struct{}{}
		<-release
		return Proof{Level: Application}, nil
	}))
	out := make(chan error, 1)
	go func() { _, err := c.Select(context.Background(), target, SelectOptions{}); out <- err }()
	await(t, started)
	c.Close()
	if err := await(t, out); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if got := c.Export().Entries[0].Selection.Strategy; got != "" {
		t.Fatal("late proof published", got)
	}
}

func BenchmarkControllerSelect(b *testing.B) {
	for _, warm := range []bool{false, true} {
		name := "cold"
		if warm {
			name = "warm"
		}
		b.Run(name, func(b *testing.B) {
			var calls atomic.Int64
			c, err := New(config(), ProbeFunc(func(context.Context, Target, string) (Proof, error) {
				calls.Add(1)
				return Proof{Level: Application}, nil
			}))
			if err != nil {
				b.Fatal(err)
			}
			defer c.Close()
			ctx := context.Background()
			if warm {
				if _, err := c.Select(ctx, target, SelectOptions{}); err != nil {
					b.Fatal(err)
				}
			}
			before := calls.Load()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := c.Select(ctx, target, SelectOptions{Refresh: !warm}); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(calls.Load()-before)/float64(b.N), "probes/op")
		})
	}
}
