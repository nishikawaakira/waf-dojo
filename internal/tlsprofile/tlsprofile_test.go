package tlsprofile

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// JA4 仕様 (FoxIO) に載っている Chrome の例。
func TestJA4SpecExample(t *testing.T) {
	h := Hello{
		CipherSuites:      []uint16{0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
		Extensions:        []uint16{0x1a1a, 0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d, 0x002b, 0x001b, 0x0015, 0x4469},
		HasSNI:            true,
		ALPN:              []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{0x2a2a, 0x0304, 0x0303},
		SignatureSchemes:  []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
	}
	if got, want := h.JA4(), "t13d1516h2_8daaf6152771_e5627efa2ab1"; got != want {
		t.Fatalf("JA4 = %s, want %s", got, want)
	}
}

func helloFromInfo(info *tls.ClientHelloInfo) Hello {
	h := Hello{
		HasSNI:            info.ServerName != "",
		ALPN:              info.SupportedProtos,
		SupportedVersions: info.SupportedVersions,
		CipherSuites:      info.CipherSuites,
		Extensions:        info.Extensions,
	}
	for _, s := range info.SignatureSchemes {
		h.SignatureSchemes = append(h.SignatureSchemes, uint16(s))
	}
	return h
}

// 生成器と同じ方法で実際に HTTPS 通信し、サーバー側 (Go の crypto/tls) が受け取った
// ClientHello から計算した JA4 が、画面に出す JA4 と一致することを確かめる。
func TestProfilesHandshakeAndJA4MatchesServerView(t *testing.T) {
	seen := make(chan Hello, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	srv.TLS = &tls.Config{GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		seen <- helloFromInfo(info)
		return nil, nil
	}}
	srv.StartTLS()
	defer srv.Close()
	// テストサーバーは 127.0.0.1 なので、SNI を送るよう localhost で接続する
	url := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)

	for name := range profiles {
		t.Run(string(name), func(t *testing.T) {
			client := &http.Client{Transport: Transport(name)}
			resp, err := client.Get(url)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			server := (<-seen).JA4()
			if got := JA4(name); got != server {
				t.Errorf("JA4 shown = %s, server saw %s", got, server)
			}
		})
	}
}

func TestBotFamilySharesCipherHash(t *testing.T) {
	part := func(n Name, i int) string { return strings.Split(JA4(n), "_")[i] }
	family := []Name{HTTPLib, BotV1, BotV2, BotV3, BotV4, BotV5}
	seen := map[string]Name{}
	for _, n := range family {
		if part(n, 1) != part(HTTPLib, 1) {
			t.Errorf("%s: cipher hash %s differs from %s", n, part(n, 1), part(HTTPLib, 1))
		}
		if prev, dup := seen[JA4(n)]; dup {
			t.Errorf("%s and %s have the same JA4 %s", n, prev, JA4(n))
		}
		seen[JA4(n)] = n
	}
	for _, n := range []Name{Chrome, Firefox, Safari, Scraper, Stuffer} {
		if part(n, 1) == part(HTTPLib, 1) {
			t.Errorf("%s must not share the bot cipher hash", n)
		}
	}
	for n := range profiles {
		t.Logf("%-10s %s", n, JA4(n))
	}
}
