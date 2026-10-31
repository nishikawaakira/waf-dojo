// Package tlsprofile は、トラフィック生成器が使う TLS の ClientHello の「型」を定義する。
//
// AWS WAF の JA4 フィンガープリントは ClientHello から計算されるため、
// ブラウザとボットで ClientHello を変えないと JA4 で見分ける練習ができない。
// uTLS を使って、ブラウザ風・ツール風の ClientHello を作り分ける。
package tlsprofile

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

type Name string

const (
	Chrome  Name = "chrome"
	Firefox Name = "firefox"
	Safari  Name = "safari"
	// Scraper はチュートリアルの攻撃ツール。ブラウザともボット群とも違う暗号スイートを持つ。
	Scraper Name = "scraper"
	// HTTPLib はゲームの「取引先の連携システム」。ボットと同じ HTTP ライブラリの素の ClientHello。
	HTTPLib Name = "httplib"
	// BotV1〜V5 は HTTPLib を少しずつ改造したボット。暗号スイートは同じなので JA4 の b 部分が共通になる。
	BotV1 Name = "bot-v1"
	BotV2 Name = "bot-v2"
	BotV3 Name = "bot-v3"
	BotV4 Name = "bot-v4"
	BotV5 Name = "bot-v5"
	// Stuffer は運用演習のリスト型攻撃ツール。JA4 は画面に出さず、ログで見つけてもらう。
	Stuffer Name = "stuffer"
)

type Profile struct {
	id      utls.ClientHelloID
	newSpec func() (*utls.ClientHelloSpec, error)
}

// ブラウザの型は HTTP/1.1 だけを ALPN で提示するように変える（生成器が HTTP/2 を話さないため）。
func browser(id utls.ClientHelloID) Profile {
	return Profile{id: utls.HelloCustom, newSpec: func() (*utls.ClientHelloSpec, error) {
		spec, err := utls.UTLSIdToSpec(id)
		if err != nil {
			return nil, err
		}
		for _, ext := range spec.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = []string{"http/1.1"}
			}
		}
		return &spec, nil
	}}
}

type botVariant struct {
	ciphers                                             []uint16
	noSNI, tls12Only, sessionTicket, statusRequest, sct bool
}

var botCiphers = []uint16{
	utls.TLS_AES_128_GCM_SHA256,
	utls.TLS_AES_256_GCM_SHA384,
	utls.TLS_CHACHA20_POLY1305_SHA256,
	utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
}

var stufferCiphers = []uint16{
	utls.TLS_AES_128_GCM_SHA256,
	utls.TLS_AES_256_GCM_SHA384,
	utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	utls.TLS_RSA_WITH_AES_128_CBC_SHA,
}

var scraperCiphers = []uint16{
	utls.TLS_AES_256_GCM_SHA384,
	utls.TLS_CHACHA20_POLY1305_SHA256,
	utls.TLS_AES_128_GCM_SHA256,
	utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
}

func bot(v botVariant) Profile {
	return Profile{id: utls.HelloCustom, newSpec: func() (*utls.ClientHelloSpec, error) {
		var exts []utls.TLSExtension
		if !v.noSNI {
			exts = append(exts, &utls.SNIExtension{})
		}
		exts = append(exts,
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384, utls.PSSWithSHA384, utls.PKCS1WithSHA384,
				utls.PSSWithSHA512, utls.PKCS1WithSHA512,
			}},
			&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
		)
		maxVers := uint16(utls.VersionTLS13)
		if v.tls12Only {
			maxVers = utls.VersionTLS12
			exts = append(exts, &utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS12}})
		} else {
			exts = append(exts,
				&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
				&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
				&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			)
		}
		if v.sessionTicket {
			exts = append(exts, &utls.SessionTicketExtension{})
		}
		if v.statusRequest {
			exts = append(exts, &utls.StatusRequestExtension{})
		}
		if v.sct {
			exts = append(exts, &utls.SCTExtension{})
		}
		ciphers := v.ciphers
		if ciphers == nil {
			ciphers = botCiphers
		}
		return &utls.ClientHelloSpec{
			CipherSuites:       ciphers,
			CompressionMethods: []byte{0},
			Extensions:         exts,
			TLSVersMin:         utls.VersionTLS12,
			TLSVersMax:         maxVers,
		}, nil
	}}
}

var profiles = map[Name]Profile{
	Chrome:  browser(utls.HelloChrome_Auto),
	Firefox: browser(utls.HelloFirefox_Auto),
	Safari:  browser(utls.HelloSafari_Auto),
	Scraper: bot(botVariant{ciphers: scraperCiphers, sessionTicket: true}),
	HTTPLib: bot(botVariant{}),
	BotV1:   bot(botVariant{sessionTicket: true}),
	BotV2:   bot(botVariant{statusRequest: true}),
	BotV3:   bot(botVariant{noSNI: true}),
	BotV4:   bot(botVariant{tls12Only: true}),
	BotV5:   bot(botVariant{sessionTicket: true, sct: true}),
	Stuffer: bot(botVariant{ciphers: stufferCiphers, statusRequest: true}),
}

// ForUserAgent はブラウザの User-Agent に合う型を返す。ブラウザ以外は Chrome 扱い。
func ForUserAgent(ua string) Name {
	switch {
	case strings.Contains(ua, "Firefox/"):
		return Firefox
	case strings.Contains(ua, "Chrome/"):
		return Chrome
	case strings.Contains(ua, "Safari/"):
		return Safari
	}
	return Chrome
}

func get(name Name) Profile {
	p, ok := profiles[name]
	if !ok {
		panic(fmt.Sprintf("tlsprofile: unknown profile %q", name))
	}
	return p
}

func (p Profile) client(conn net.Conn, serverName string) (*utls.UConn, error) {
	// 送信先は自分の環境の ALB (自己署名証明書) なので、証明書の検証はしない。
	cfg := &utls.Config{ServerName: serverName, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}
	uconn := utls.UClient(conn, cfg, p.id)
	if p.newSpec != nil {
		spec, err := p.newSpec()
		if err != nil {
			return nil, err
		}
		if err := uconn.ApplyPreset(spec); err != nil {
			return nil, err
		}
	}
	return uconn, nil
}

// Transport はこの型の ClientHello で HTTPS 接続する http.Transport を返す。
func Transport(name Name) *http.Transport {
	p := get(name)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			raw, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			uconn, err := p.client(raw, host)
			if err == nil {
				err = uconn.HandshakeContext(ctx)
			}
			if err != nil {
				raw.Close()
				return nil, err
			}
			return uconn, nil
		},
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     30 * time.Second,
	}
}

var (
	ja4Mu    sync.Mutex
	ja4Cache = map[Name]string{}
)

// JA4 はこの型の ClientHello を（通信せずに）組み立てて JA4 を計算する。
func JA4(name Name) string {
	ja4Mu.Lock()
	defer ja4Mu.Unlock()
	if v, ok := ja4Cache[name]; ok {
		return v
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	uconn, err := get(name).client(c1, "shop.wafdojo.example")
	if err == nil {
		err = uconn.BuildHandshakeState()
	}
	if err != nil {
		panic(fmt.Sprintf("tlsprofile: build %s: %v", name, err))
	}
	hello, err := ParseClientHello(uconn.HandshakeState.Hello.Raw)
	if err != nil {
		panic(fmt.Sprintf("tlsprofile: parse %s: %v", name, err))
	}
	v := hello.JA4()
	ja4Cache[name] = v
	return v
}
