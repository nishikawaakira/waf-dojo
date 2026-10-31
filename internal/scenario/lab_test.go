package scenario

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// matchCount は、パターンの n 件のリクエストのうち、block がブロックした件数を返す。
func matchCount(t *testing.T, block func(Request) (bool, error), p Pattern, n int, rng *rand.Rand) int {
	t.Helper()
	hits := 0
	for i := 0; i < n; i++ {
		ok, err := block(p.Make(rng))
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			hits++
		}
	}
	return hits
}

// 模範解答が「攻撃をすべて止め、正常な通信を 1 件も止めない」こと、
// ありがちな失敗ルールが本当に失敗する（すり抜けか誤検知が起きる）ことを、全問題で確かめる。
func TestLabSolutionsAreCorrectAndPitfallsFail(t *testing.T) {
	const n = 40
	labs := Labs()
	if len(labs) < 25 {
		t.Fatalf("got %d lab problems, want at least 25", len(labs))
	}
	levels := map[int]int{}
	var checked []*Scenario
	for _, s := range All() {
		if s.HasReference() {
			checked = append(checked, s)
		}
	}
	if len(checked) < len(labs)+len(Exams())+len(OpsDrills()) {
		t.Fatal("every lab, exam, and ops drill needs a reference solution")
	}
	for _, s := range checked {
		t.Run(s.ID, func(t *testing.T) {
			if s.Lab {
				levels[s.Level]++
			}
			if s.Lab && (len(s.Conditions) == 0 || s.CVE == "") {
				t.Fatal("lab problems need conditions and a CVE/CWE")
			}
			if !s.HideSolution && len(s.SolutionNote) == 0 {
				t.Fatal("visible solutions need notes")
			}
			if s.Level == 3 && (s.Pitfall == nil || len(s.Hints) == 0) {
				t.Fatal("level 3 problems need a pitfall and hints")
			}
			rng := rand.New(rand.NewPCG(7, uint64(len(s.ID))))
			pitfallMissed, pitfallFalsePositive := false, false
			for _, p := range s.Patterns {
				hits := matchCount(t, s.ReferenceBlocks, p, n, rng)
				label := p.Label.In(Japanese)
				if p.Kind == Attack && hits != n {
					t.Errorf("solution misses attack %q: %d/%d blocked", label, hits, n)
				}
				if p.Kind == Benign && hits != 0 {
					t.Errorf("solution blocks benign %q: %d/%d", label, hits, n)
				}
				if s.Pitfall != nil {
					ph := matchCount(t, s.PitfallBlocks, p, n, rng)
					pitfallMissed = pitfallMissed || (p.Kind == Attack && ph < n)
					pitfallFalsePositive = pitfallFalsePositive || (p.Kind == Benign && ph > 0)
				}
			}
			if s.Pitfall != nil && !pitfallMissed && !pitfallFalsePositive {
				t.Errorf("pitfall %s should miss an attack or block legitimate traffic, but it is perfect", s.Pitfall.Name)
			}
			if s.Pitfall != nil && len(s.PitfallNote) == 0 {
				t.Error("pitfall needs an explanation")
			}
		})
	}
	for level := 1; level <= 4; level++ {
		if levels[level] == 0 {
			t.Errorf("no level %d problems", level)
		}
	}
}

// ラボのリクエストは、送り先のダミーアプリと予約ドメイン以外を指していないこと。
func TestLabPayloadsUseReservedDomains(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 1))
	for _, s := range Labs() {
		for _, p := range s.Patterns {
			raw := FormatRequest(p.Make(rng))
			for _, word := range []string{"evil.com", "attacker.com", "burpcollaborator", "oast."} {
				if strings.Contains(strings.ToLower(raw), word) {
					t.Errorf("%s: payload should use reserved domains (*.example), found %q", s.ID, word)
				}
			}
		}
	}
}
