package tlsprofile

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Hello は JA4 の計算に必要な ClientHello の要素。
type Hello struct {
	LegacyVersion     uint16
	CipherSuites      []uint16
	Extensions        []uint16 // 出現順
	HasSNI            bool
	ALPN              []string
	SupportedVersions []uint16
	SignatureSchemes  []uint16 // 出現順
}

const (
	extSNI               = 0x0000
	extSignatureSchemes  = 0x000d
	extALPN              = 0x0010
	extSupportedVersions = 0x002b
)

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

func withoutGREASE(xs []uint16) []uint16 {
	out := make([]uint16, 0, len(xs))
	for _, x := range xs {
		if !isGREASE(x) {
			out = append(out, x)
		}
	}
	return out
}

func hexList(xs []uint16) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprintf("%04x", x)
	}
	return strings.Join(parts, ",")
}

func hash12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func versionCode(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	}
	return "00"
}

func alpnCode(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	first, last := alpn[0][0], alpn[0][len(alpn[0])-1]
	isAlnum := func(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
	if !isAlnum(first) || !isAlnum(last) {
		h := hex.EncodeToString([]byte(alpn[0]))
		return string(h[0]) + string(h[len(h)-1])
	}
	return string(first) + string(last)
}

// JA4 は TCP 上の TLS として JA4 (a_b_c) を計算する。
//
//	a: t + TLS バージョン + SNI の有無 (d/i) + 暗号スイート数 + 拡張数 + ALPN の先頭と末尾の文字
//	b: 暗号スイートを並べ替えて SHA-256 した先頭 12 文字
//	c: 拡張 (SNI と ALPN を除く) を並べ替えたもの + "_" + 署名アルゴリズム (出現順) の SHA-256 先頭 12 文字
//
// GREASE の値はどれにも含めない。
func (h Hello) JA4() string {
	version := h.LegacyVersion
	if vs := withoutGREASE(h.SupportedVersions); len(vs) > 0 {
		version = vs[0]
		for _, v := range vs {
			version = max(version, v)
		}
	}
	sni := "i"
	if h.HasSNI {
		sni = "d"
	}
	ciphers := withoutGREASE(h.CipherSuites)
	exts := withoutGREASE(h.Extensions)
	a := fmt.Sprintf("t%s%s%02d%02d%s", versionCode(version), sni, min(len(ciphers), 99), min(len(exts), 99), alpnCode(h.ALPN))

	sortedCiphers := append([]uint16(nil), ciphers...)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	b := hash12(hexList(sortedCiphers))

	var sortedExts []uint16
	for _, e := range exts {
		if e != extSNI && e != extALPN {
			sortedExts = append(sortedExts, e)
		}
	}
	sort.Slice(sortedExts, func(i, j int) bool { return sortedExts[i] < sortedExts[j] })
	c := "000000000000"
	if len(sortedExts) > 0 {
		s := hexList(sortedExts)
		if sigs := withoutGREASE(h.SignatureSchemes); len(sigs) > 0 {
			s += "_" + hexList(sigs)
		}
		c = hash12(s)
	}
	return a + "_" + b + "_" + c
}

type reader struct{ b []byte }

var errShort = errors.New("client hello is truncated")

func (r *reader) bytes(n int) ([]byte, error) {
	if len(r.b) < n {
		return nil, errShort
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out, nil
}

func (r *reader) u8() (int, error) {
	b, err := r.bytes(1)
	if err != nil {
		return 0, err
	}
	return int(b[0]), nil
}

func (r *reader) u16() (int, error) {
	b, err := r.bytes(2)
	if err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(b)), nil
}

func (r *reader) vec8() (*reader, error) {
	n, err := r.u8()
	if err != nil {
		return nil, err
	}
	b, err := r.bytes(n)
	return &reader{b}, err
}

func (r *reader) vec16() (*reader, error) {
	n, err := r.u16()
	if err != nil {
		return nil, err
	}
	b, err := r.bytes(n)
	return &reader{b}, err
}

func (r *reader) u16s() ([]uint16, error) {
	var out []uint16
	for len(r.b) > 0 {
		v, err := r.u16()
		if err != nil {
			return nil, err
		}
		out = append(out, uint16(v))
	}
	return out, nil
}

// ParseClientHello は ClientHello のハンドシェイクメッセージ（先頭 4 バイトのヘッダー付き）を読む。
func ParseClientHello(msg []byte) (Hello, error) {
	var h Hello
	if len(msg) < 4 || msg[0] != 1 {
		return h, errors.New("not a client hello")
	}
	r := &reader{msg[4:]}
	v, err := r.u16()
	if err != nil {
		return h, err
	}
	h.LegacyVersion = uint16(v)
	if _, err := r.bytes(32); err != nil { // random
		return h, err
	}
	if _, err := r.vec8(); err != nil { // session id
		return h, err
	}
	cs, err := r.vec16()
	if err != nil {
		return h, err
	}
	if h.CipherSuites, err = cs.u16s(); err != nil {
		return h, err
	}
	if _, err := r.vec8(); err != nil { // compression methods
		return h, err
	}
	if len(r.b) == 0 {
		return h, nil
	}
	exts, err := r.vec16()
	if err != nil {
		return h, err
	}
	for len(exts.b) > 0 {
		typ, err := exts.u16()
		if err != nil {
			return h, err
		}
		data, err := exts.vec16()
		if err != nil {
			return h, err
		}
		h.Extensions = append(h.Extensions, uint16(typ))
		switch typ {
		case extSNI:
			h.HasSNI = true
		case extALPN:
			list, err := data.vec16()
			if err != nil {
				return h, err
			}
			for len(list.b) > 0 {
				p, err := list.vec8()
				if err != nil {
					return h, err
				}
				h.ALPN = append(h.ALPN, string(p.b))
			}
		case extSupportedVersions:
			list, err := data.vec8()
			if err != nil {
				return h, err
			}
			if h.SupportedVersions, err = list.u16s(); err != nil {
				return h, err
			}
		case extSignatureSchemes:
			list, err := data.vec16()
			if err != nil {
				return h, err
			}
			if h.SignatureSchemes, err = list.u16s(); err != nil {
				return h, err
			}
		}
	}
	return h, nil
}
