package scenario

import (
	"fmt"
	"math/rand/v2"
	"net/url"
	"strings"
	"testing"
)

func TestScenariosAreWellFormed(t *testing.T) {
	if len(Tutorials()) != 6 || len(Games()) != 6 || len(Labs()) < 25 {
		t.Fatalf("got %d tutorials / %d games / %d labs", len(Tutorials()), len(Games()), len(Labs()))
	}
	rng := rand.New(rand.NewPCG(1, 1))
	for _, s := range All() {
		var attacks, benign int
		for _, p := range s.Patterns {
			if p.Count <= 0 {
				t.Errorf("%s/%s: count must be positive", s.ID, p.Label)
			}
			req := p.Make(rng)
			if !strings.HasPrefix(req.Path, "/") {
				t.Errorf("%s/%s: path %q must start with /", s.ID, p.Label, req.Path)
			}
			// User-Agent は明示的に指定する (空なら「送らない」という意味)
			if _, ok := req.Headers["User-Agent"]; !ok || req.ClientIP == "" {
				t.Errorf("%s/%s: User-Agent and ClientIP are required", s.ID, p.Label)
			}
			if p.Kind == Attack {
				attacks++
			} else {
				benign++
			}
		}
		if attacks == 0 || benign == 0 {
			t.Errorf("%s: needs both attack and benign traffic", s.ID)
		}
		if s.Tutorial && len(s.Steps) == 0 {
			t.Errorf("%s: tutorials need steps", s.ID)
		}
		for i, st := range s.Steps {
			if len(st.Detail) == 0 {
				t.Errorf("%s: step %d needs a detail explaining its settings", s.ID, i+1)
			}
		}
		if s.Category() == CategoryGame && (len(s.Hints) == 0 || s.PrepSeconds == 0) {
			t.Errorf("%s: game stages need hints and prep time", s.ID)
		}
		if s.Warmup >= s.Duration {
			t.Errorf("%s: warmup must be shorter than duration", s.ID)
		}
		want := 2
		if s.HideAttackSamples {
			want--
		}
		if s.HideBenignSamples {
			want--
		}
		if v := s.View(Japanese); len(v.Samples) < want {
			t.Errorf("%s: view has %d samples, want %d", s.ID, len(v.Samples), want)
		}
		if s.HideSolution && s.SolutionView(Japanese) != nil {
			t.Errorf("%s: hidden solutions must not be exposed", s.ID)
		}
	}
}

// すべての文章に、対応しているすべての言語の訳があることを確かめる。
func TestEveryTextIsTranslated(t *testing.T) {
	check := func(where string, txt Text) {
		for _, l := range Langs {
			if strings.TrimSpace(txt[l]) == "" {
				t.Errorf("%s: missing %q translation", where, l)
			}
		}
	}
	checkAll := func(where string, ts []Text) {
		for i, txt := range ts {
			check(fmt.Sprintf("%s[%d]", where, i), txt)
		}
	}
	for _, s := range All() {
		check(s.ID+".Title", s.Title)
		check(s.ID+".Summary", s.Summary)
		checkAll(s.ID+".Topics", s.Topics)
		checkAll(s.ID+".Briefing", s.Briefing)
		checkAll(s.ID+".Lesson", s.Lesson)
		for i, st := range s.Steps {
			check(fmt.Sprintf("%s.Steps[%d]", s.ID, i), st.Do)
			checkAll(fmt.Sprintf("%s.Steps[%d].Detail", s.ID, i), st.Detail)
		}
		checkAll(s.ID+".Hints", s.Hints)
		checkAll(s.ID+".Conditions", s.Conditions)
		checkAll(s.ID+".SolutionNote", s.SolutionNote)
		checkAll(s.ID+".PitfallNote", s.PitfallNote)
		for _, p := range s.Patterns {
			check(s.ID+".Pattern", p.Label)
		}
		// 英語の画面に日本語の文章が紛れ込んでいないか（リクエスト例の中身は除く）
		v := s.View(English)
		texts := append(append([]string{v.Title, v.Summary}, v.Briefing...), v.Hints...)
		for _, st := range v.Steps {
			texts = append(append(texts, st.Text), st.Detail...)
		}
		texts = append(append(texts, v.Conditions...), v.Topics...)
		if sv := s.SolutionView(English); sv != nil {
			texts = append(append(texts, sv.Notes...), sv.PitfallNote...)
		}
		for _, str := range texts {
			if hasJapanese(str) {
				t.Errorf("%s: English view contains Japanese: %q", s.ID, str)
			}
		}
	}
}

func hasJapanese(s string) bool {
	for _, r := range s {
		if r >= 0x3040 && r <= 0x30ff || r >= 0x4e00 && r <= 0x9fff {
			return true
		}
	}
	return false
}

func TestLangParsing(t *testing.T) {
	cases := map[string]Lang{"en": English, "EN-us": English, "ja": Japanese, "ja-JP": Japanese}
	for in, want := range cases {
		if got, ok := ParseLang(in); !ok || got != want {
			t.Errorf("ParseLang(%q) = %q, %v", in, got, ok)
		}
	}
	if _, ok := ParseLang("fr"); ok {
		t.Error("fr should not be supported yet")
	}
	if got, _ := LangFromAcceptLanguage("fr-FR,fr;q=0.9,en-US;q=0.8,ja;q=0.7"); got != English {
		t.Errorf("Accept-Language = %q, want en", got)
	}
	if got := T("日本語", "").In(English); got != "日本語" {
		t.Errorf("fallback = %q", got)
	}
}

// ALB は、1 回デコードするとルートより上に遡るパスを WAF より前に 400 で拒否する（実環境で確認）。
// そのようなパスを送ると採点できないので、どのシナリオのパスもルートの中にとどまることを確かめる。
func TestPathsStayWithinRoot(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 5))
	for _, s := range All() {
		for _, p := range s.Patterns {
			path := p.Make(rng).Path
			decoded, err := url.PathUnescape(path)
			if err != nil {
				decoded = path
			}
			depth := 0
			for _, seg := range strings.Split(decoded, "/") {
				switch seg {
				case "", ".":
				case "..":
					depth--
				default:
					depth++
				}
				if depth < 0 {
					t.Errorf("%s: %q climbs above the root, so ALB would reject it with 400", s.ID, path)
					break
				}
			}
		}
	}
}
