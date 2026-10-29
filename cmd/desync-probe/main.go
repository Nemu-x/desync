// Command desync-probe measures which desync strategies reach which sites on
// the network it runs on, and writes a report that is safe to share.
//
// For every target it resolves the name once with the system resolver, then
// for every strategy dials TCP, wraps the socket with desync, completes a TLS
// handshake with real certificate verification and sends one HEAD request.
// A strategy "works" for a site when the verified server answered over HTTP.
//
//	desync-probe                       # default sites and strategies, report.json next to the binary
//	desync-probe -targets youtube.com,discord.com
//	desync-probe -list my-sites.txt -presets tlsrec-1s,split-1s
//	desync-probe -tlsrec 3+s -split 1+s -name my-try   # adds a custom strategy
package main

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

//go:embed targets.txt
var defaultTargets string

const usageText = `desync-probe checks which desync strategies open which sites on this network.

Run it without arguments: it tests a built-in list of sites with every strategy
this system supports, prints a summary and writes report.json next to the
program. Send report.json back to whoever asked you to run it.

How it measures: each site name is resolved once with the system resolver.
Then, for every strategy, the program connects to the site, applies the
strategy to the TLS ClientHello, completes a TLS handshake that verifies the
real certificate, and sends one HTTP HEAD request. "works" means every run
succeeded, "flaky" some, "fails" none. Blocked sites are an expected result:
the program exits with code 0 unless it could not run at all.

Privacy: the report contains the site names, the server addresses they
resolved to, which strategies worked, error classes and timings, plus the
program version, OS and CPU type. It does NOT contain your IP addresses (local
or public), MAC address, computer name or user name. DNS answers that are not
public server addresses are recorded only as "non-public", and error messages
are stripped of addresses. Nothing is uploaded; the program only connects to
the listed sites.

Usage: desync-probe [flags]

`

func main() {
	os.Exit(mainErr(os.Args[1:], os.Stdout, os.Stderr))
}

func mainErr(args []string, stdout, stderr io.Writer) int {
	code := runMain(args, stdout, stderr)
	if len(args) == 0 {
		waitIfOwnConsole()
	}
	return code
}

func runMain(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("desync-probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	targetsFlag := fs.String("targets", "", "comma-separated sites to test, e.g. youtube.com,discord.com (replaces the built-in list)")
	listFlag := fs.String("list", "", "file with one site per line (replaces the built-in list; '#' starts a comment)")
	port := fs.Int("port", 443, "TCP port for sites given without one")
	presetsFlag := fs.String("presets", "all", "strategies to test: all, or comma-separated names (see -list-presets); none is always included")
	listPresets := fs.Bool("list-presets", false, "print the strategies available on this system and exit")
	repeat := fs.Int("repeat", 2, "runs per site and strategy, to tell flaky from failing (1-10)")
	timeout := fs.Duration("timeout", 6*time.Second, "limit for one run (connect, TLS and HTTP together) and for one DNS lookup")
	concurrency := fs.Int("concurrency", 8, "runs in progress at the same time (1-64)")
	budget := fs.Duration("budget", 20*time.Minute, "limit for the whole measurement; runs not started by then are reported as not run (0: none)")
	jsonPath := fs.String("json", "", "where to write the report (default: report.json next to the program; \"none\" disables)")
	dnsServer := fs.String("dns", "", "resolve names with this DNS server (IP or IP:port) instead of the system resolver")
	quiet := fs.Bool("q", false, "do not print a line per run")
	showVersion := fs.Bool("version", false, "print the version and exit")
	var c customFlags
	fs.StringVar(&c.name, "name", "custom", "name of the custom strategy given with the flags below")
	fs.StringVar(&c.tlsrec, "tlsrec", "", "custom strategy: TLS record split positions, e.g. 1+s,3+s (desync-socks notation)")
	fs.StringVar(&c.split, "split", "", "custom strategy: TCP write split positions, e.g. 1+s")
	fs.DurationVar(&c.delay, "split-delay", 0, "custom strategy: pause between TCP pieces")
	fs.StringVar(&c.wait, "split-wait", "none", "custom strategy: wait for none, sent or acked before each further piece")
	fs.DurationVar(&c.waitTimeout, "split-wait-timeout", 0, "custom strategy: bound for each split wait (0: library default)")
	fs.BoolVar(&c.disorder, "disorder", false, "custom strategy: send the first TCP piece with hop limit 1 (needs -split)")
	fs.BoolVar(&c.oob, "oob", false, "custom strategy: one out-of-band byte after the first TCP piece (needs -split)")
	fs.StringVar(&c.oobByte, "oob-byte", "a", "custom strategy: the out-of-band byte, one character or 0xNN")
	fs.IntVar(&c.fake, "fake", 0, "custom strategy: TCP fake prefix (Windows, Linux); -1 means all but the last byte")
	fs.IntVar(&c.ttl, "ttl", 4, "custom strategy: TTL of the fake first transmission")
	fs.DurationVar(&c.fakeTimeout, "fake-timeout", 3*time.Second, "custom strategy: limit of a native fake operation")
	fs.Usage = func() {
		fmt.Fprint(stderr, usageText)
		fs.PrintDefaults()
		fmt.Fprint(stderr, "\nExamples:\n  desync-probe\n  desync-probe -targets youtube.com,discord.com -repeat 3\n  desync-probe -list sites.txt -presets tlsrec-1s,split-1s -json result.json\n  desync-probe -tlsrec 3+s -split 1+s -name mine\n")
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected argument %q (sites go in -targets)\n", fs.Arg(0))
		return 2
	}
	if *showVersion {
		t := currentToolInfo()
		fmt.Fprintf(stdout, "desync-probe %s (library %s, %s, %s/%s)\n", t.Version, t.LibraryVersion, t.GoVersion, runtime.GOOS, runtime.GOARCH)
		return 0
	}
	fail := func(format string, a ...interface{}) int {
		fmt.Fprintf(stderr, "desync-probe: "+format+"\n", a...)
		return 2
	}
	if *repeat < 1 || *repeat > 10 {
		return fail("-repeat must be between 1 and 10")
	}
	if *concurrency < 1 || *concurrency > 64 {
		return fail("-concurrency must be between 1 and 64")
	}
	if *timeout <= 0 || *timeout > 2*time.Minute {
		return fail("-timeout must be between 0 and 2m")
	}
	if *budget < 0 {
		return fail("-budget must not be negative")
	}
	if *port < 1 || *port > 65535 {
		return fail("-port must be between 1 and 65535")
	}

	caps := platformCapabilities()
	presets, skipped := availablePresets(caps)
	if c.set() {
		cp, err := c.preset()
		if err != nil {
			return fail("%v", err)
		}
		if presets, err = addCustom(presets, cp); err != nil {
			return fail("%v", err)
		}
		if *presetsFlag == "all" && !flagSet(fs, "presets") {
			// A custom strategy alone is compared with the direct connection.
			*presetsFlag = cp.Name
		} else if *presetsFlag != "all" {
			*presetsFlag += "," + cp.Name
		}
	}
	if *listPresets {
		printPresets(stdout, presets, skipped)
		return 0
	}
	selected, err := selectPresets(presets, *presetsFlag)
	if err != nil {
		return fail("%v", err)
	}

	text := defaultTargets
	switch {
	case *targetsFlag != "" && *listFlag != "":
		return fail("use -targets or -list, not both")
	case *targetsFlag != "":
		text = *targetsFlag
	case *listFlag != "":
		b, err := os.ReadFile(*listFlag)
		if err != nil {
			return fail("%v", err)
		}
		text = string(b)
	}
	targets, err := parseTargets(text, *port)
	if err != nil {
		return fail("%v", err)
	}
	if len(targets) == 0 {
		return fail("no targets")
	}

	settings := settingsInfo{Repeat: *repeat, Concurrency: *concurrency, TimeoutMS: ms(*timeout), BudgetMS: ms(*budget), Resolver: "system"}
	p := &prober{timeout: *timeout, userAgent: "desync-probe/" + currentToolInfo().Version}
	if *dnsServer != "" {
		lookup, err := serverLookup(*dnsServer)
		if err != nil {
			return fail("%v", err)
		}
		p.lookup, settings.Resolver = lookup, "custom"
	} else if lookup := androidLookup(); lookup != nil {
		p.lookup, settings.Resolver = lookup, "system (termux resolv.conf)"
	}

	out := *jsonPath
	if out == "" {
		out = defaultReportPath()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	total := len(targets) * len(selected) * *repeat
	fmt.Fprintf(stderr, "desync-probe %s: %d sites x %d strategies x %d runs = %d connections (at most %d at a time, %s each)\n",
		currentToolInfo().Version, len(targets), len(selected), *repeat, total, *concurrency, *timeout)
	if len(skipped) > 0 {
		fmt.Fprintf(stderr, "%d strategies are not available on this system (listed at the end).\n", len(skipped))
	}
	fmt.Fprintln(stderr, "Press Ctrl+C to stop early; the results so far are still written.")
	started := time.Now()
	var progress func(progressEvent)
	if !*quiet {
		progress = func(e progressEvent) { fmt.Fprintln(stderr, progressLine(e)) }
	}
	res := run(ctx, p, targets, selected, runConfig{Repeat: *repeat, Concurrency: *concurrency, Budget: *budget}, progress)
	rep := buildReport(started, caps, settings, selected, skipped, targets, res)
	printSummary(stdout, rep)

	if out != "none" {
		if path, err := writeReport(out, rep, *jsonPath == ""); err != nil {
			fmt.Fprintf(stderr, "\ndesync-probe: could not write the report: %v\n", err)
			return 1
		} else {
			fmt.Fprintf(stdout, "\nReport written to %s\nSend this file back; it contains no personal addresses or names.\n", path)
		}
	}
	return 0
}

func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func progressLine(e progressEvent) string {
	width := len(fmt.Sprint(e.Total))
	head := fmt.Sprintf("[%*d/%d]", width, e.Done, e.Total)
	r := e.Result
	switch {
	case r == nil:
		return fmt.Sprintf("%s skip  %s  %s", head, e.Target, e.Preset.Name)
	case r.ok():
		return fmt.Sprintf("%s ok    %s  %s  (HTTP %d, %d ms)", head, e.Target, e.Preset.Name, r.Status, ms(r.Dial+r.TLS+r.FirstByte))
	}
	return fmt.Sprintf("%s FAIL  %s  %s  (%s at %s)", head, e.Target, e.Preset.Name, r.Class, r.Stage)
}

func printPresets(w io.Writer, presets []preset, skipped []skippedPreset) {
	fmt.Fprintln(w, "Strategies available on this system (name, ID, description):")
	for _, p := range presets {
		fmt.Fprintf(w, "  %-20s %s  %s\n", p.Name, p.ID(), p.Description)
	}
	if len(skipped) > 0 {
		fmt.Fprintln(w, "\nNot available here:")
		for _, s := range skipped {
			fmt.Fprintf(w, "  %-20s %s\n", s.Name, s.Reason)
		}
	}
}

// defaultReportPath is report.json next to the executable, or in the
// current directory for a binary built by go run.
func defaultReportPath() string {
	exe, err := os.Executable()
	if err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		dir := filepath.Dir(exe)
		if !strings.Contains(dir, "go-build") {
			return filepath.Join(dir, "report.json")
		}
	}
	return "report.json"
}

// writeReport writes rep to path. When the default location is not writable
// (for example a read-only folder), it falls back to the current directory.
func writeReport(path string, rep report, fallback bool) (string, error) {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "", err
	}
	b = append(b, '\n')
	err = os.WriteFile(path, b, 0o644)
	if err != nil && fallback && filepath.Base(path) != path {
		path = "report.json"
		err = os.WriteFile(path, b, 0o644)
	}
	if err != nil {
		return "", err
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	return path, nil
}

// serverLookup resolves through one DNS server instead of the system
// configuration.
func serverLookup(server string) (func(context.Context, string) ([]net.IP, error), error) {
	addr := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		addr = net.JoinHostPort(server, "53")
	}
	host, _, _ := net.SplitHostPort(addr)
	if net.ParseIP(host) == nil {
		return nil, fmt.Errorf("-dns wants an IP address, got %q", server)
	}
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}}
	return func(ctx context.Context, h string) ([]net.IP, error) {
		addrs, err := r.LookupIPAddr(ctx, h)
		if err != nil {
			return nil, err
		}
		out := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, a.IP)
		}
		return out, nil
	}, nil
}

// androidLookup handles Termux: Go's resolver reads /etc/resolv.conf, which
// Android does not have, while Termux keeps its resolver configuration under
// $PREFIX/etc. It returns nil everywhere else.
func androidLookup() func(context.Context, string) ([]net.IP, error) {
	if runtime.GOOS != "android" {
		return nil
	}
	if _, err := os.Stat("/etc/resolv.conf"); err == nil {
		return nil
	}
	prefix := os.Getenv("PREFIX")
	if prefix == "" {
		prefix = "/data/data/com.termux/files/usr"
	}
	f, err := os.Open(filepath.Join(prefix, "etc", "resolv.conf"))
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" && net.ParseIP(fields[1]) != nil {
			lookup, err := serverLookup(fields[1])
			if err == nil {
				return lookup
			}
		}
	}
	return nil
}
