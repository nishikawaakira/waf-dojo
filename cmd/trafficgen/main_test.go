package main

import (
	"context"
	"crypto/tls"
	"errors"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"wafdy/internal/scenario"
	"wafdy/internal/score"
	"wafdy/internal/tlsprofile"
)

// localURL は SNI が送られるよう、テストサーバーにホスト名で接続する URL を返す。
func localURL(srv *httptest.Server) string {
	return strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
}

func TestRunScoresAgainstFakeWAF(t *testing.T) {
	// "UNION" を含むクエリだけ 403 を返す、WAF の代わりのサーバー
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "" {
			t.Errorf("X-Forwarded-For is missing")
		}
		if strings.Contains(r.URL.RawQuery, "UNION") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	get := func(q string) func(*rand.Rand) scenario.Request {
		return func(*rand.Rand) scenario.Request {
			return scenario.Request{Path: "/search", RawQuery: "q=" + q, Headers: map[string]string{"User-Agent": "test"}, ClientIP: "192.0.2.1"}
		}
	}
	sc := &scenario.Scenario{
		Duration: 200 * time.Millisecond,
		Patterns: []scenario.Pattern{
			{Kind: scenario.Attack, Label: scenario.T("union", "union"), Count: 5, Make: get("1+UNION+SELECT")},
			{Kind: scenario.Attack, Label: scenario.T("or", "or"), Count: 5, Make: get("%27+OR+1%3D1")},
			{Kind: scenario.Benign, Label: scenario.T("search", "search"), Count: 10, Make: get("shoes")},
		},
	}

	res := score.Compute(run(context.Background(), localURL(srv), sc), false)
	if res.AttackBlocked != 5 || res.AttackTotal != 10 || res.BenignBlocked != 0 || res.Errors != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.Score != 50 {
		t.Fatalf("score = %d, want 50", res.Score)
	}
}

func TestSendTreatsWAFActionHeaderAsBlocked(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-amzn-waf-action", "challenge")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	blocked, err := send(context.Background(), localURL(srv), scenario.Request{Path: "/", ClientIP: "192.0.2.1"})
	if err != nil || !blocked {
		t.Fatalf("blocked=%v err=%v, want blocked", blocked, err)
	}
}

func TestRunUsesRequestedTLSProfile(t *testing.T) {
	// ClientHello の JA4 でスクレイパーを見分け、ハンドシェイクを拒否するサーバー
	botJA4 := tlsprofile.JA4(tlsprofile.Scraper)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		h := tlsprofile.Hello{HasSNI: info.ServerName != "", ALPN: info.SupportedProtos, SupportedVersions: info.SupportedVersions, CipherSuites: info.CipherSuites, Extensions: info.Extensions}
		for _, s := range info.SignatureSchemes {
			h.SignatureSchemes = append(h.SignatureSchemes, uint16(s))
		}
		if h.JA4() == botJA4 {
			return nil, errors.New("blocked by fingerprint")
		}
		return nil, nil
	}}
	srv.StartTLS()
	defer srv.Close()

	ok, err := send(context.Background(), localURL(srv), scenario.Request{Path: "/", ClientIP: "192.0.2.1", Headers: map[string]string{"User-Agent": "Mozilla/5.0 Chrome/141.0.0.0"}})
	if err != nil || ok {
		t.Fatalf("browser profile: blocked=%v err=%v, want allowed", ok, err)
	}
	if _, err := send(context.Background(), localURL(srv), scenario.Request{Path: "/", ClientIP: "192.0.2.1", TLS: tlsprofile.Scraper}); err == nil {
		t.Fatal("scraper profile should have been rejected by its JA4")
	}
}

// すべてのシナリオのリクエストが、パスとクエリを書き換えられずにそのまま送られることを確かめる。
// (/vpn/../vpns/ や %252e のような PoC の形が崩れると、問題の意味がなくなるため)
func TestRequestsAreSentVerbatim(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 3))
	for _, s := range scenario.All() {
		for _, p := range s.Patterns {
			r := p.Make(rng)
			req, err := newRequest(context.Background(), "https://shop.wafdojo.example", r)
			if err != nil {
				t.Errorf("%s: %v", s.ID, err)
				continue
			}
			if got := req.URL.RequestURI(); got != r.Target() {
				t.Errorf("%s: request target changed: sent %q, want %q", s.ID, got, r.Target())
			}
		}
	}
}

func TestBadRequestIsNotCountedAsBlocked(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	blocked, err := send(context.Background(), localURL(srv), scenario.Request{Path: "/", ClientIP: "192.0.2.1"})
	if blocked || err == nil {
		t.Fatalf("blocked=%v err=%v, want an error and not blocked", blocked, err)
	}
}
