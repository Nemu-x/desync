package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nemu-x/desync"
)

func TestRunConcurrencyAndTimeoutBounds(t *testing.T) {
	port := rawServer(t, silent)
	var targets []target
	for i := 0; i < 6; i++ {
		targets = append(targets, target{Host: "site" + strconv.Itoa(i) + ".test", Port: port})
	}
	presets := []preset{{Name: baselineName}, {Name: "tlsrec-1s", Opts: desync.Options{TLSRec: posList("1+s")}}, {Name: "split-1", Opts: desync.Options{Split: posList("1")}}}
	d := &countingDialer{}
	p := loopbackProber(nil, 200*time.Millisecond)
	p.dial = d.dial
	var events int64
	start := time.Now()
	res := run(context.Background(), p, targets, presets, runConfig{Repeat: 2, Concurrency: 3}, func(progressEvent) { atomic.AddInt64(&events, 1) })
	elapsed := time.Since(start)
	jobs := len(targets) * len(presets) * 2
	if peak := atomic.LoadInt64(&d.peak); peak > 3 || peak < 2 {
		t.Errorf("peak open connections %d, want 2..3", peak)
	}
	if d.dials != int64(jobs) || events != int64(jobs) {
		t.Errorf("dials %d, events %d, want %d", d.dials, events, jobs)
	}
	if open := atomic.LoadInt64(&d.open); open != 0 {
		t.Errorf("%d connections left open", open)
	}
	// 36 attempts of 200 ms, three at a time: about 2.4 s.
	if min, max := 2*time.Second, 6*time.Second; elapsed < min || elapsed > max {
		t.Errorf("run took %v, want %v..%v", elapsed, min, max)
	}
	for i := range targets {
		for j := range presets {
			s := summarize(res.Pairs[i][j])
			if s.Outcome != outcomeFails || s.Class != classTimeout || s.Run != 2 {
				t.Errorf("%d/%d: %+v", i, j, s)
			}
		}
	}
	if res.Incomplete {
		t.Error("run without a budget reported incomplete")
	}
}

func TestRunBudget(t *testing.T) {
	port := rawServer(t, silent)
	targets := []target{{Host: "a.test", Port: port}, {Host: "b.test", Port: port}}
	presets := []preset{{Name: baselineName}, {Name: "tlsrec-1s", Opts: desync.Options{TLSRec: posList("1+s")}}}
	p := loopbackProber(nil, 400*time.Millisecond)
	start := time.Now()
	res := run(context.Background(), p, targets, presets, runConfig{Repeat: 5, Concurrency: 1, Budget: 900 * time.Millisecond}, nil)
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("budget 900ms, run took %v", el)
	}
	if !res.Incomplete {
		t.Fatal("exhausted budget not reported")
	}
	ran, skipped := 0, 0
	for i := range targets {
		for j := range presets {
			for _, a := range res.Pairs[i][j].Attempts {
				if a == nil {
					skipped++
				} else {
					ran++
					if a.Class != classTimeout {
						t.Errorf("attempt cut by the budget recorded as %s", a.Class)
					}
				}
			}
		}
	}
	if ran == 0 || skipped == 0 || ran+skipped != 20 {
		t.Fatalf("ran %d, skipped %d", ran, skipped)
	}
}

func TestRunDNSFailure(t *testing.T) {
	p := &prober{timeout: time.Second, lookup: func(_ context.Context, host string) ([]net.IP, error) {
		return nil, &net.DNSError{Err: "server misbehaving", Name: host, Server: "192.168.1.1:53"}
	}}
	res := run(context.Background(), p, []target{{Host: "gone.test", Port: 443}}, []preset{{Name: baselineName}}, runConfig{Repeat: 2, Concurrency: 2}, nil)
	if res.DNS[0].Err == nil || res.Address[0] != nil || res.Incomplete {
		t.Fatalf("dns failure: %+v", res)
	}
	if s := summarize(res.Pairs[0][0]); s.Outcome != outcomeNotRun {
		t.Fatalf("outcome %s", s.Outcome)
	}
	rep := buildReport(time.Now(), desync.PlatformCapabilities(), settingsInfo{}, []preset{{Name: baselineName}}, nil, []target{{Host: "gone.test", Port: 443}}, res)
	if d := rep.Targets[0].DNS; d.Status != "failed" || strings.Contains(d.Error, "192.168") {
		t.Fatalf("dns info %+v", d)
	}
}

func TestSummarize(t *testing.T) {
	ok := &attemptResult{Stage: stageDone}
	reset := &attemptResult{Stage: stageTLS, Class: classReset}
	to := &attemptResult{Stage: stageTLS, Class: classTimeout}
	cases := []struct {
		in   []*attemptResult
		want summary
	}{
		{[]*attemptResult{ok, ok}, summary{Outcome: outcomeWorks, OK: 2, Run: 2}},
		{[]*attemptResult{ok, reset}, summary{Outcome: outcomeFlaky, OK: 1, Run: 2, Class: classReset}},
		{[]*attemptResult{to, reset, reset}, summary{Outcome: outcomeFails, Run: 3, Class: classReset}},
		{[]*attemptResult{nil, nil}, summary{Outcome: outcomeNotRun}},
	}
	for _, c := range cases {
		if got := summarize(pairResult{Attempts: c.in}); got != c.want {
			t.Errorf("%+v: got %+v", c.want, got)
		}
	}
}

// A loopback "filter" resets connections whose first segment carries the
// server name; strategies that split the name pass it. This also produces
// the sample terminal output (go test -run TestLoopbackSummary -v).
func TestLoopbackSummary(t *testing.T) {
	f := newTLSFixture(t, false)
	filtered := dpiProxy(t, goodHost, f.port)
	presets := platformPresets(t)
	targets := []target{{Host: goodHost, Port: f.port}, {Host: goodHost, Port: filtered}, {Host: goodHost, Port: rawServer(t, silent)}}
	p := loopbackProber(f.roots, 1500*time.Millisecond)
	res := run(context.Background(), p, targets, presets, runConfig{Repeat: 2, Concurrency: 16}, nil)
	rep := buildReport(time.Now(), desync.PlatformCapabilities(), settingsInfo{Repeat: 2}, presets, nil, targets, res)
	var out bytes.Buffer
	printSummary(&out, rep)
	t.Log("\n" + out.String())

	byName := func(ti int, name string) resultInfo {
		for _, r := range rep.Targets[ti].Results {
			if r.Name == name {
				return r
			}
		}
		t.Fatalf("no result for %s", name)
		return resultInfo{}
	}
	if r := byName(0, baselineName); r.Outcome != outcomeWorks {
		t.Errorf("direct to the open server: %+v", r)
	}
	if r := byName(1, baselineName); r.Outcome != outcomeFails || r.Class != classReset {
		t.Errorf("direct through the filter: %+v", r)
	}
	if r := byName(1, "tlsrec-1s"); r.Outcome != outcomeWorks {
		t.Errorf("tlsrec-1s through the filter: %+v", r)
	}
	if r := byName(2, "tlsrec-1s"); r.Outcome != outcomeFails || r.Class != classTimeout {
		t.Errorf("silent server: %+v", r)
	}
	if !strings.Contains(out.String(), "tlsrec-1s") || !strings.Contains(out.String(), "fails (reset, 0/2)") {
		t.Errorf("summary lacks the expected lines")
	}
}

func TestMainWritesReportAndExitsZero(t *testing.T) {
	port := rawServer(t, resetAfterHello)
	dir := t.TempDir()
	path := filepath.Join(dir, "r.json")
	var stdout, stderr bytes.Buffer
	code := runMain([]string{"-targets", "127.0.0.1:" + strconv.Itoa(port), "-presets", "tlsrec-1s", "-repeat", "1", "-timeout", "3s", "-json", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rep report
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Strategies) != 2 || len(rep.Targets) != 1 || rep.Targets[0].Results[0].Outcome != outcomeFails {
		t.Fatalf("report %+v", rep)
	}
	if !strings.Contains(stderr.String(), "FAIL") || !strings.Contains(stdout.String(), "Report written to") {
		t.Fatalf("output:\n%s\n%s", stdout.String(), stderr.String())
	}

	// Custom strategy alone: compared only with the baseline.
	stdout.Reset()
	stderr.Reset()
	code = runMain([]string{"-targets", "127.0.0.1:" + strconv.Itoa(port), "-tlsrec", "2+s", "-name", "mine", "-repeat", "1", "-json", path, "-q"}, &stdout, &stderr)
	if code != 0 || strings.Contains(stderr.String(), "FAIL") {
		t.Fatalf("custom run exit %d:\n%s\n%s", code, stdout.String(), stderr.String())
	}
	b, _ = os.ReadFile(path)
	rep = report{}
	if err := json.Unmarshal(b, &rep); err != nil || len(rep.Strategies) != 2 || rep.Strategies[0].Name != baselineName || rep.Strategies[1].Name != "mine" {
		t.Fatalf("custom report: %v %+v", err, rep.Strategies)
	}

	for _, args := range [][]string{{"-h"}, {"-list-presets"}, {"-version"}} {
		stdout.Reset()
		stderr.Reset()
		if code := runMain(args, &stdout, &stderr); code != 0 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	if !strings.Contains(stdout.String(), "desync-probe") {
		t.Errorf("-version output %q", stdout.String())
	}
	for _, args := range [][]string{{"-repeat", "0"}, {"-presets", "nope"}, {"extra"}, {"-disorder"}, {"-targets", "a", "-list", "b"}} {
		if code := runMain(args, &stdout, &stderr); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

func TestWriteReportFallback(t *testing.T) {
	dir := t.TempDir()
	wd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)
	path, err := writeReport(filepath.Join(dir, "missing", "report.json"), report{Schema: reportSchema}, true)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "report.json" || filepath.Dir(path) == filepath.Join(dir, "missing") {
		t.Fatalf("fallback path %s", path)
	}
	if _, err := writeReport(filepath.Join(dir, "missing", "report.json"), report{}, false); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("explicit path must not fall back: %v", err)
	}
}
