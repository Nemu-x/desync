package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Nemu-x/desync"
)

// reportSchema changes when a field of the JSON report changes meaning.
const reportSchema = "desync-probe/v1"

// libraryModule is the module path of the desync library.
const libraryModule = "github.com/Nemu-x/desync"

// version is set at release build time with -ldflags "-X main.version=...".
var version = ""

// report is the JSON document. It holds target names, public server
// addresses and outcomes only: no local or public address of the machine
// running the probe, no MAC address, host name or user name.
type report struct {
	Schema       string              `json:"schema"`
	Tool         toolInfo            `json:"tool"`
	Platform     platformInfo        `json:"platform"`
	Capabilities desync.Capabilities `json:"capabilities"`
	Settings     settingsInfo        `json:"settings"`
	Started      string              `json:"started_utc"`
	ElapsedMS    int64               `json:"elapsed_ms"`
	Incomplete   bool                `json:"incomplete"` // the budget ran out or the run was interrupted
	Strategies   []strategyInfo      `json:"strategies"`
	Skipped      []skippedInfo       `json:"skipped_strategies"`
	Targets      []targetInfo        `json:"targets"`
}

type toolInfo struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	LibraryVersion string `json:"library_version"`
	GoVersion      string `json:"go_version"`
	VCSRevision    string `json:"vcs_revision,omitempty"`
	VCSTime        string `json:"vcs_time,omitempty"`
	VCSModified    bool   `json:"vcs_modified,omitempty"`
}

type platformInfo struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type settingsInfo struct {
	Repeat      int    `json:"repeat"`
	Concurrency int    `json:"concurrency"`
	TimeoutMS   int64  `json:"attempt_timeout_ms"`
	BudgetMS    int64  `json:"budget_ms"`
	Resolver    string `json:"resolver"` // "system" or "custom"; the server address is not recorded
}

type strategyInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Key         string `json:"key"`
}

type skippedInfo struct {
	Name   string `json:"name"`
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

type targetInfo struct {
	Host    string       `json:"host"`
	Port    int          `json:"port"`
	DNS     dnsInfo      `json:"dns"`
	Address string       `json:"address,omitempty"` // the server address measured
	Results []resultInfo `json:"results"`
}

type dnsInfo struct {
	Status    string   `json:"status"` // resolved or failed
	Addresses []string `json:"addresses,omitempty"`
	Error     string   `json:"error,omitempty"`
	MS        int64    `json:"ms"`
}

type resultInfo struct {
	Strategy string        `json:"strategy"` // strategy ID
	Name     string        `json:"name"`
	Outcome  string        `json:"outcome"`               // works, flaky, fails, not-run
	Class    string        `json:"error_class,omitempty"` // most frequent class of the failed runs
	OK       int           `json:"ok"`
	Run      int           `json:"run"`
	Attempts []attemptInfo `json:"attempts"`
}

type attemptInfo struct {
	Run         bool   `json:"run"`
	DialOK      bool   `json:"dial_ok"`
	TLSOK       bool   `json:"tls_ok"`
	HTTPOK      bool   `json:"http_ok"`
	Stage       string `json:"stage,omitempty"` // where a failed attempt stopped: dial, tls, http
	ErrorClass  string `json:"error_class,omitempty"`
	Error       string `json:"error,omitempty"`
	HTTPStatus  int    `json:"http_status,omitempty"`
	Proto       string `json:"proto,omitempty"`
	TLSVersion  string `json:"tls_version,omitempty"`
	DialMS      int64  `json:"dial_ms,omitempty"`
	TLSMS       int64  `json:"tls_ms,omitempty"`
	FirstByteMS int64  `json:"first_byte_ms,omitempty"`
}

func ms(d time.Duration) int64 { return d.Milliseconds() }

// buildReport converts a run into the shareable report.
func buildReport(started time.Time, caps desync.Capabilities, settings settingsInfo, presets []preset, skipped []skippedPreset, targets []target, res runResult) report {
	r := report{
		Schema:       reportSchema,
		Tool:         currentToolInfo(),
		Platform:     platformInfo{OS: runtime.GOOS, Arch: runtime.GOARCH},
		Capabilities: caps,
		Settings:     settings,
		Started:      started.UTC().Format(time.RFC3339),
		ElapsedMS:    ms(res.Elapsed),
		Incomplete:   res.Incomplete,
		Strategies:   []strategyInfo{},
		Skipped:      []skippedInfo{},
		Targets:      []targetInfo{},
	}
	for _, p := range presets {
		r.Strategies = append(r.Strategies, strategyInfo{ID: p.ID(), Name: p.Name, Description: p.Description, Key: p.Opts.Key()})
	}
	for _, s := range skipped {
		r.Skipped = append(r.Skipped, skippedInfo{Name: s.Name, Key: s.Key, Reason: scrub(s.Reason, nil)})
	}
	for i, t := range targets {
		d := res.DNS[i]
		allowed := publicSet(d.IPs)
		ti := targetInfo{Host: t.Host, Port: t.Port, DNS: dnsInfo{MS: ms(d.Duration)}, Results: []resultInfo{}}
		if d.Err != nil {
			ti.DNS.Status = "failed"
			ti.DNS.Error = dnsError(d.Err)
		} else {
			ti.DNS.Status = "resolved"
			for _, ip := range d.IPs {
				ti.DNS.Addresses = append(ti.DNS.Addresses, shareableIP(ip))
			}
			ti.Address = shareableIP(res.Address[i])
		}
		for j, p := range presets {
			pr := res.Pairs[i][j]
			s := summarize(pr)
			ri := resultInfo{Strategy: p.ID(), Name: p.Name, Outcome: s.Outcome, Class: s.Class, OK: s.OK, Run: s.Run, Attempts: []attemptInfo{}}
			for _, a := range pr.Attempts {
				ri.Attempts = append(ri.Attempts, attemptJSON(a, allowed))
			}
			ti.Results = append(ti.Results, ri)
		}
		r.Targets = append(r.Targets, ti)
	}
	return r
}

func attemptJSON(a *attemptResult, allowed map[string]bool) attemptInfo {
	if a == nil {
		return attemptInfo{}
	}
	out := attemptInfo{
		Run:        true,
		DialOK:     a.Stage != stageDial,
		TLSOK:      a.Stage == stageHTTP || a.Stage == stageDone,
		HTTPOK:     a.Stage == stageDone,
		ErrorClass: a.Class,
		HTTPStatus: a.Status,
		Proto:      a.Proto,
		TLSVersion: a.TLSVersion,
		DialMS:     ms(a.Dial),
		TLSMS:      ms(a.TLS),
	}
	if out.HTTPOK {
		out.FirstByteMS = ms(a.FirstByte)
	} else {
		out.Stage = a.Stage
		out.Error = errorText(a.Err, allowed)
	}
	return out
}

// isPublic reports whether ip is a globally routed unicast address. Other
// answers (loopback, private, link-local, carrier-grade NAT, benchmark and
// fake-IP ranges) could describe the tester's own network.
func isPublic(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking, also fake-IP DNS of local proxies
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
}

// nonPublicAddress replaces an answer that is not a public server address.
const nonPublicAddress = "non-public"

func shareableIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if !isPublic(ip) {
		return nonPublicAddress
	}
	return ip.String()
}

func publicSet(ips []net.IP) map[string]bool {
	m := map[string]bool{}
	for _, ip := range ips {
		if isPublic(ip) {
			m[ip.String()] = true
		}
	}
	return m
}

// errorText describes err without the local socket address that Go's
// network errors include, then scrubs any remaining address.
func errorText(err error, allowed map[string]bool) string {
	if err == nil {
		return ""
	}
	return scrub(describe(err), allowed)
}

func describe(err error) string {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Op + ": " + describe(op.Err)
	}
	var sys *os.SyscallError
	if errors.As(err, &sys) && sys.Err != nil {
		return sys.Syscall + ": " + sys.Err.Error()
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return dnsError(dns)
	}
	return err.Error()
}

// dnsError omits the resolver address (often the home router) from err.
func dnsError(err error) string {
	var dns *net.DNSError
	if !errors.As(err, &dns) {
		if errors.Is(err, context.DeadlineExceeded) {
			return "lookup timed out"
		}
		return scrub(err.Error(), nil)
	}
	switch {
	case dns.IsNotFound:
		return "no such host"
	case dns.IsTimeout:
		return "lookup timed out"
	}
	return scrub(dns.Err, nil)
}

var (
	ipv4Pattern = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	ipv6Pattern = regexp.MustCompile(`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%[0-9A-Za-z_.\-]+)?`)
	macPattern  = regexp.MustCompile(`\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b`)
)

// scrub replaces every IP address not in allowed, and every MAC address, so
// no text that reaches the report can carry the tester's addresses.
func scrub(s string, allowed map[string]bool) string {
	s = macPattern.ReplaceAllString(s, "<mac>")
	replace := func(m string) string {
		a, err := netip.ParseAddr(m)
		if err != nil {
			return m
		}
		if allowed[a.Unmap().String()] {
			return m
		}
		return "<addr>"
	}
	s = ipv6Pattern.ReplaceAllStringFunc(s, replace)
	s = ipv4Pattern.ReplaceAllStringFunc(s, replace)
	if len(s) > 240 {
		s = s[:240] + "..."
	}
	return s
}

func currentToolInfo() toolInfo {
	t := toolInfo{Name: "desync-probe", Version: version, GoVersion: runtime.Version()}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		if t.Version == "" {
			t.Version = "unknown"
		}
		return t
	}
	if bi.Main.Path == libraryModule {
		t.LibraryVersion = bi.Main.Version
	}
	for _, d := range bi.Deps {
		if d.Path == libraryModule {
			t.LibraryVersion = d.Version
			if d.Replace != nil && d.Replace.Version != "" {
				t.LibraryVersion = d.Replace.Version
			}
		}
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			t.VCSRevision = s.Value
		case "vcs.time":
			t.VCSTime = s.Value
		case "vcs.modified":
			t.VCSModified = s.Value == "true"
		}
	}
	if t.Version == "" {
		t.Version = bi.Main.Version
	}
	if t.Version == "" {
		t.Version = "(devel)"
	}
	if t.LibraryVersion == "" || (bi.Main.Path == libraryModule && t.LibraryVersion == "(devel)") {
		// Built from this repository: the library is the same checkout.
		t.LibraryVersion = t.Version
	}
	return t
}

func sortedStrings(s []string) []string {
	sort.Strings(s)
	return s
}

// printSummary writes the readable result: one block per site, then the
// strategies ranked by how many reachable sites they opened.
func printSummary(w io.Writer, rep report) {
	fmt.Fprintf(w, "\nResults (%s %s on %s/%s, %d runs per strategy)\n", rep.Tool.Name, rep.Tool.Version, rep.Platform.OS, rep.Platform.Arch, rep.Settings.Repeat)
	fmt.Fprintln(w, "works = every run succeeded, flaky = some runs succeeded (shown as name~), fails = none did")
	if rep.Incomplete {
		fmt.Fprintln(w, "Note: the run stopped early (time budget or Ctrl+C); some runs did not happen.")
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "\nSITE\tDNS\tDIRECT\tWORKS WITH")
	for _, t := range rep.Targets {
		host := t.Host
		if t.Port != 443 {
			host = net.JoinHostPort(t.Host, fmt.Sprint(t.Port))
		}
		if t.DNS.Status != "resolved" {
			fmt.Fprintf(tw, "%s\tfailed (%s)\t-\t-\n", host, t.DNS.Error)
			continue
		}
		direct := "-"
		var works, flaky []string
		others := 0
		for _, r := range t.Results {
			if r.Name == baselineName {
				direct = outcomeText(r)
				continue
			}
			if r.Outcome != outcomeNotRun {
				others++
			}
			switch r.Outcome {
			case outcomeWorks:
				works = append(works, r.Name)
			case outcomeFlaky:
				flaky = append(flaky, r.Name+"~")
			}
		}
		lines := wrapNames(fmt.Sprintf("%d/%d", len(works), others), append(works, flaky...), 72)
		fmt.Fprintf(tw, "%s\tok\t%s\t%s\n", host, direct, lines[0])
		for _, l := range lines[1:] {
			fmt.Fprintf(tw, "\t\t\t  %s\n", l)
		}
	}
	tw.Flush()

	// Rank strategies by the sites they reached where the direct connection
	// did not fully work; those are the ones the tester cares about.
	type rank struct {
		name          string
		helped, tried int
	}
	var ranks []rank
	for j, s := range rep.Strategies {
		if s.Name == baselineName {
			continue
		}
		rk := rank{name: s.Name}
		for _, t := range rep.Targets {
			if t.DNS.Status != "resolved" || len(t.Results) <= j {
				continue
			}
			base := baselineResult(t)
			if base == nil || base.Outcome == outcomeWorks || base.Outcome == outcomeNotRun {
				continue
			}
			rk.tried++
			if t.Results[j].Outcome == outcomeWorks {
				rk.helped++
			}
		}
		ranks = append(ranks, rk)
	}
	sort.SliceStable(ranks, func(a, b int) bool { return ranks[a].helped > ranks[b].helped })
	if len(ranks) > 0 && ranks[0].tried > 0 {
		fmt.Fprintf(w, "\nStrategies that opened sites where the direct connection failed (%d sites):\n", ranks[0].tried)
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		none := 0
		for _, rk := range ranks {
			if rk.helped == 0 {
				none++
				continue
			}
			fmt.Fprintf(tw, "  %s\t%d of %d\n", rk.name, rk.helped, rk.tried)
		}
		tw.Flush()
		if none > 0 {
			fmt.Fprintf(w, "  (%d other strategies opened none of them)\n", none)
		}
	} else {
		fmt.Fprintln(w, "\nEvery reachable site worked directly; nothing to compare.")
	}
	var local []string
	seen := map[string]bool{}
	for _, t := range rep.Targets {
		if t.Address == nonPublicAddress && !seen[t.Host] {
			seen[t.Host] = true
			local = append(local, t.Host)
		}
	}
	if len(local) > 0 {
		fmt.Fprintf(w, "\nNote: %d site(s) resolved to a non-public address (%s). A local proxy, VPN\n"+
			"or DNS filter answers for them, so their results do not describe the network itself.\n",
			len(local), strings.Join(local, ", "))
	}
	if len(rep.Skipped) > 0 {
		fmt.Fprintln(w, "\nNot available on this system:")
		for _, s := range rep.Skipped {
			fmt.Fprintf(w, "  %s: %s\n", s.Name, s.Reason)
		}
	}
}

func baselineResult(t targetInfo) *resultInfo {
	for i := range t.Results {
		if t.Results[i].Name == baselineName {
			return &t.Results[i]
		}
	}
	return nil
}

func outcomeText(r resultInfo) string {
	switch r.Outcome {
	case outcomeWorks:
		return "works"
	case outcomeNotRun:
		return "not run"
	}
	return fmt.Sprintf("%s (%s, %d/%d)", r.Outcome, r.Class, r.OK, r.Run)
}

// wrapNames joins head and names into lines of at most width characters.
func wrapNames(head string, names []string, width int) []string {
	if len(names) == 0 {
		return []string{head}
	}
	lines := []string{head + ":"}
	for _, n := range names {
		last := &lines[len(lines)-1]
		if len(*last)+1+len(n) > width && *last != head+":" {
			lines = append(lines, n)
			continue
		}
		if *last != "" {
			*last += " "
		}
		*last += n
	}
	return lines
}
