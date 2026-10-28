package controller_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"time"

	"github.com/Nemu-x/desync"
	"github.com/Nemu-x/desync/controller"
)

// A consumer supplies its own endpoint, immutable strategy catalog, certificate
// verification and application success contract. This example owns the server;
// the library has no implicit public-service probes.
func ExampleController_Select() {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead || r.URL.Path != "/probe" {
			http.Error(w, "unexpected probe", 400)
			return
		}
		w.Header().Set("X-Probe-Contract", "local-v1")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	host, portText, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portText)
	catalog := map[string]desync.Options{"record-8": {TLSRec: []desync.Pos{{Offset: 8}}}}
	trust := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	probe := controller.ProbeFunc(func(ctx context.Context, target controller.Target, id string) (controller.Proof, error) {
		transport := &http.Transport{DisableKeepAlives: true, DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			raw, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			cfg := trust.Clone()
			cfg.ServerName = target.Host
			conn := tls.Client(desync.WrapConn(raw, catalog[id]), cfg)
			if err := conn.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return conn, nil
		}}
		defer transport.CloseIdleConnections()
		endpoint := url.URL{Scheme: "https", Host: net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port))), Path: "/probe"}
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint.String(), nil)
		if err != nil {
			return controller.Proof{}, err
		}
		response, err := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			return controller.Proof{}, err
		}
		defer response.Body.Close()
		io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		if response.StatusCode != http.StatusNoContent || response.Header.Get("X-Probe-Contract") != "local-v1" {
			return controller.Proof{}, fmt.Errorf("unexpected application response")
		}
		return controller.Proof{Level: controller.Application, Code: "expected_response"}, nil
	})
	c, err := controller.New(controller.Config{Candidates: []string{"record-8"}, PolicyVersion: "example-v1"}, probe)
	if err != nil {
		panic(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	target := controller.Target{Network: "owned-loopback", Host: host, Port: uint16(port), ProbeID: "head-probe-local-v1"}
	first, err := c.Select(ctx, target, controller.SelectOptions{})
	if err != nil {
		panic(err)
	}
	second, err := c.Select(ctx, target, controller.SelectOptions{})
	if err != nil {
		panic(err)
	}
	fmt.Println(first.Strategy, first.Source, second.Source)
	// Output: record-8 probe cache
}
