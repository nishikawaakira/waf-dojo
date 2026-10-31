package scenario

import (
	"os"
	"path/filepath"
	"testing"

	"wafdy/internal/wafrule"
)

// WAFDY_EXPORT_RULES=<dir> を付けて実行すると、ラボの模範解答と失敗ルールを 1 ファイルずつ書き出す。
// AWS の CheckCapacity API で文法を確かめるときに使う。
func TestExportLabRules(t *testing.T) {
	dir := os.Getenv("WAFDY_EXPORT_RULES")
	if dir == "" {
		t.Skip("set WAFDY_EXPORT_RULES to export")
	}
	for _, s := range All() {
		solution := ruleJSON(s.Solution)
		if len(s.SolutionACL) > 0 {
			solution = wafrule.ACLJSON(s.SolutionACL)
		} else if solution != "" {
			solution = "[" + solution + "]"
		}
		pitfall := ruleJSON(s.Pitfall)
		if pitfall != "" {
			pitfall = "[" + pitfall + "]"
		}
		for _, r := range []*struct {
			name string
			json string
		}{{s.ID + ".solution", solution}, {s.ID + ".pitfall", pitfall}} {
			if r.json == "" {
				continue
			}
			if err := os.WriteFile(filepath.Join(dir, r.name+".json"), []byte(r.json), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}
