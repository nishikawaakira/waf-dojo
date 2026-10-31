package scenario

import "strings"

// Lang は画面の言語。言語を増やすときは、ここに追加して Langs に並べ、
// 各シナリオの Text に訳を足す（訳がない場合は英語、次に日本語で表示する）。
type Lang string

const (
	Japanese Lang = "ja"
	English  Lang = "en"
)

var Langs = []Lang{Japanese, English}

// ParseLang は "en"・"ja-JP" などから対応している言語を返す。
func ParseLang(s string) (Lang, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, l := range Langs {
		if s == string(l) || strings.HasPrefix(s, string(l)+"-") {
			return l, true
		}
	}
	return "", false
}

// LangFromAcceptLanguage は Accept-Language ヘッダーの先頭から順に、対応している言語を探す。
func LangFromAcceptLanguage(header string) (Lang, bool) {
	for _, part := range strings.Split(header, ",") {
		tag, _, _ := strings.Cut(part, ";")
		if l, ok := ParseLang(tag); ok {
			return l, true
		}
	}
	return "", false
}

// Text は言語ごとの文字列。
type Text map[Lang]string

// T は日本語と英語の Text を作る。
func T(ja, en string) Text {
	return Text{Japanese: ja, English: en}
}

func (t Text) In(l Lang) string {
	for _, cand := range []Lang{l, English, Japanese} {
		if s := t[cand]; s != "" {
			return s
		}
	}
	return ""
}

func in(ts []Text, l Lang) []string {
	if len(ts) == 0 {
		return nil
	}
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.In(l)
	}
	return out
}
