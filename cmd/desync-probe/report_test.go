package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Nemu-x/desync"
)

// loopbackReport runs a few presets against loopback servers and returns the
// marshaled report.
func loopbackReport(t *testing.T) ([]byte, report) {
	t.Helper()
	f := newTLSFixture(t, true)
	presets := platformPresets(t)
	if len(presets) > 4 {
		presets = presets[:4]
	}
	targets := []target{{Host: goodHost, Port: f.port}, {Host: goodHost, Port: rawServer(t, resetAfterHello)}, {Host: "wrong-name.test", Port: f.port}}
	p := loopbackProber(f.roots, 3*time.Second)
	res := run(context.Background(), p, targets, presets, runConfig{Repeat: 2, Concurrency: 4}, nil)
	_, skipped := buildCatalog(catalog(), desync.Capabilities{OS: "test", Unsupported: map[string]string{"fake-tcp": "not here"}})
	rep := buildReport(time.Now(), desync.PlatformCapabilities(), settingsInfo{Repeat: 2, Concurrency: 4, TimeoutMS: 3000, Resolver: "system"}, presets, skipped, targets, res)
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return b, rep
}

func TestReportPrivacy(t *testing.T) {
	b, _ := loopbackReport(t)
	text := string(b)
	forbidden := []string{"127.0.0.1", "[::1]", "localhost"}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			forbidden = append(forbidden, ipn.IP.String())
		}
	}
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		if len(i.HardwareAddr) > 0 {
			forbidden = append(forbidden, i.HardwareAddr.String(), strings.ToUpper(i.HardwareAddr.String()))
		}
	}
	if h, err := os.Hostname(); err == nil && len(h) >= 3 {
		forbidden = append(forbidden, h, strings.ToLower(h))
	}
	for _, env := range []string{"USER", "USERNAME", "LOGNAME"} {
		if u := os.Getenv(env); len(u) >= 3 {
			forbidden = append(forbidden, `"`+u+`"`, `\\`+u+`\\`, "/"+u+"/")
		}
	}
	if wd, err := os.Getwd(); err == nil {
		forbidden = append(forbidden, wd)
	}
	for _, s := range forbidden {
		if strings.Contains(text, s) {
			t.Errorf("report contains %q", s)
		}
	}
	if !strings.Contains(text, `"address": "`+nonPublicAddress+`"`) {
		t.Error("loopback answer not recorded as non-public")
	}
}

func TestReportSchema(t *testing.T) {
	b, rep := loopbackReport(t)
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema", "tool", "platform", "capabilities", "settings", "started_utc", "elapsed_ms", "incomplete", "strategies", "skipped_strategies", "targets"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing top-level %q", k)
		}
	}
	if m["schema"] != reportSchema {
		t.Errorf("schema %v", m["schema"])
	}
	tool := m["tool"].(map[string]interface{})
	for _, k := range []string{"name", "version", "library_version", "go_version"} {
		if s, _ := tool[k].(string); s == "" {
			t.Errorf("tool.%s empty", k)
		}
	}
	caps := m["capabilities"].(map[string]interface{})
	for _, k := range []string{"OS", "FakeTCP", "OOB", "Disorder", "Ack", "Unsupported"} {
		if _, ok := caps[k]; !ok {
			t.Errorf("capabilities.%s missing", k)
		}
	}
	for _, s := range rep.Strategies {
		if s.ID == "" || s.Name == "" || !strings.HasPrefix(s.Key, "desync/") {
			t.Errorf("strategy %+v", s)
		}
	}
	if len(rep.Skipped) == 0 || rep.Skipped[0].Reason == "" {
		t.Errorf("skipped %+v", rep.Skipped)
	}
	if len(rep.Targets) != 3 {
		t.Fatalf("targets %d", len(rep.Targets))
	}
	for _, ti := range rep.Targets {
		if ti.DNS.Status != "resolved" || len(ti.Results) != len(rep.Strategies) {
			t.Errorf("target %+v", ti)
		}
		for i, r := range ti.Results {
			if r.Strategy != rep.Strategies[i].ID || len(r.Attempts) != 2 {
				t.Errorf("result order/attempts %+v", r)
			}
		}
	}
	ok := rep.Targets[0].Results[0].Attempts[0]
	if !ok.Run || !ok.DialOK || !ok.TLSOK || !ok.HTTPOK || ok.HTTPStatus != 204 || ok.Proto != "HTTP/2.0" || ok.ErrorClass != "" || ok.Stage != "" {
		t.Errorf("successful attempt %+v", ok)
	}
	reset := rep.Targets[1].Results[0].Attempts[0]
	if !reset.DialOK || reset.TLSOK || reset.ErrorClass != classReset || reset.Stage != stageTLS || reset.Error == "" {
		t.Errorf("reset attempt %+v", reset)
	}
	cert := rep.Targets[2].Results[0]
	if cert.Outcome != outcomeFails || cert.Class != classCert {
		t.Errorf("certificate result %+v", cert)
	}
}

func TestScrub(t *testing.T) {
	allowed := map[string]bool{"203.0.113.9": true, "2001:4860::8888": true}
	in := "dial tcp 192.168.1.5:50123->203.0.113.9:443: fe80::1%eth0 [2001:4860::8888]:443 [2a02:6b8::1]:5 00:1A:2b:3c:4d:5e ::ffff:10.0.0.1 at 12:30:45"
	got := scrub(in, allowed)
	for _, bad := range []string{"192.168", "fe80", "2a02", "1A:2b", "10.0.0.1"} {
		if strings.Contains(got, bad) {
			t.Errorf("scrub kept %q: %s", bad, got)
		}
	}
	for _, keep := range []string{"203.0.113.9:443", "[2001:4860::8888]:443", "12:30:45"} {
		if !strings.Contains(got, keep) {
			t.Errorf("scrub removed %q: %s", keep, got)
		}
	}
	op := &net.OpError{Op: "read", Net: "tcp",
		Source: &net.TCPAddr{IP: net.IPv4(192, 168, 7, 7), Port: 5555},
		Addr:   &net.TCPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 443},
		Err:    os.NewSyscallError("wsarecv", errors.New("connection reset"))}
	if s := errorText(op, nil); s != "read: wsarecv: connection reset" {
		t.Errorf("errorText = %q", s)
	}
	dns := &net.DNSError{Err: "no such host", Name: "x.test", Server: "192.168.1.1:53", IsNotFound: true}
	if s := errorText(dns, nil); strings.Contains(s, "192.168") || s != "no such host" {
		t.Errorf("dns errorText = %q", s)
	}
	if len(scrub(strings.Repeat("x", 1000), nil)) > 250 {
		t.Error("long text not truncated")
	}
}

func TestIsPublic(t *testing.T) {
	for _, s := range []string{"8.8.8.8", "142.250.74.110", "2a00:1450:4001::200e", "::ffff:8.8.4.4"} {
		if !isPublic(net.ParseIP(s)) {
			t.Errorf("%s not public", s)
		}
	}
	for _, s := range []string{"127.0.0.1", "10.10.34.34", "192.168.0.1", "172.16.0.1", "100.64.1.1", "169.254.1.1", "198.18.0.5", "0.0.0.0", "::1", "fe80::1", "fd00::1", "224.0.0.1", "2001:db8::1"} {
		if isPublic(net.ParseIP(s)) {
			t.Errorf("%s public", s)
		}
	}
	if shareableIP(net.ParseIP("10.0.0.1")) != nonPublicAddress || shareableIP(net.ParseIP("8.8.8.8")) != "8.8.8.8" {
		t.Error("shareableIP")
	}
}
