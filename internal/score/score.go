// Package score はトラフィック生成の結果からスコアを計算する。
package score

import (
	"math"
	"time"

	"wafdy/internal/scenario"
)

// HintMultiplier はヒントを見た場合にスコアへ掛ける倍率。
const HintMultiplier = 0.8

// Outcome は 1 リクエストの結果。
type Outcome struct {
	Kind scenario.Kind
	// Key は同じパターンのリクエストをまとめるためのキー。
	Key     string
	Label   scenario.Text
	Blocked bool
	Err     bool
	// Scored が false のものは集計に含めない（ウォームアップ中の攻撃など）。
	Scored bool
	// At は攻撃開始からの経過時間。
	At time.Duration
}

// PropagationWindow は、ルールを保存した直後で WAF への反映が間に合っていない可能性がある時間。
const PropagationWindow = 15 * time.Second

// LabelResult の Label は全言語分を保存し、画面側で表示する言語を選ぶ。
type LabelResult struct {
	Label   scenario.Text `json:"label"`
	Kind    scenario.Kind `json:"kind"`
	Total   int           `json:"total"`
	Blocked int           `json:"blocked"`
}

type Result struct {
	AttackTotal       int     `json:"attackTotal"`
	AttackBlocked     int     `json:"attackBlocked"`
	BenignTotal       int     `json:"benignTotal"`
	BenignBlocked     int     `json:"benignBlocked"`
	Errors            int     `json:"errors"`
	DetectionRate     float64 `json:"detectionRate"`
	FalsePositiveRate float64 `json:"falsePositiveRate"`
	HintUsed          bool    `json:"hintUsed"`
	// PropagationSuspects は、ルールの反映待ちだった可能性が高い結果の件数。
	// 採点には含めたまま、画面で「反映が終わっていなかった可能性」を伝えるのに使う。
	PropagationSuspects int           `json:"propagationSuspects,omitempty"`
	Score               int           `json:"score"`
	Labels              []LabelResult `json:"labels"`
}

// propagationDelays は、ルールの反映待ちで判定が遅れた可能性が高い結果 (outcomes の添字) を返す。
//
// ルールを保存してから WAF 全体に反映されるまで数十秒かかるため、攻撃開始の直後だけ結果が変わることがある。
// 次の両方を満たすものだけを反映待ちの可能性ありとする (本当の設定ミスと区別するため)。
//   - 開始から PropagationWindow 以内の結果である
//   - 同じ種類のリクエストが、PropagationWindow 以降は 1 件残らず逆の結果になっている
//     (攻撃なら全件ブロック、正常な通信なら全件通過)
func propagationDelays(outcomes []Outcome) map[int]bool {
	type later struct{ total, blocked int }
	after := map[string]*later{}
	for _, o := range outcomes {
		if !o.Scored || o.Err || o.At < PropagationWindow {
			continue
		}
		key := string(o.Kind) + "\x00" + o.Key
		if after[key] == nil {
			after[key] = &later{}
		}
		after[key].total++
		if o.Blocked {
			after[key].blocked++
		}
	}
	suspects := map[int]bool{}
	for n, o := range outcomes {
		if !o.Scored || o.Err || o.At >= PropagationWindow {
			continue
		}
		l := after[string(o.Kind)+"\x00"+o.Key]
		if l == nil || l.total == 0 {
			continue
		}
		leakedThenFixed := o.Kind == scenario.Attack && !o.Blocked && l.blocked == l.total
		overblockedThenFixed := o.Kind == scenario.Benign && o.Blocked && l.blocked == 0
		if leakedThenFixed || overblockedThenFixed {
			suspects[n] = true
		}
	}
	return suspects
}

// Compute はスコアを計算する。
//
//	スコア = 100 × 検知率 × (1 − 誤検知率)   （ヒント使用時は × 0.8）
//
// 通信エラーになったリクエストは分母から除く。ルールの反映待ちの可能性がある結果も採点にはそのまま含める。
func Compute(outcomes []Outcome, hintUsed bool) Result {
	res := Result{HintUsed: hintUsed}
	res.PropagationSuspects = len(propagationDelays(outcomes))
	index := map[string]int{}
	for _, o := range outcomes {
		if !o.Scored {
			continue
		}
		if o.Err {
			res.Errors++
			continue
		}
		key := string(o.Kind) + "\x00" + o.Key
		i, ok := index[key]
		if !ok {
			i = len(res.Labels)
			index[key] = i
			res.Labels = append(res.Labels, LabelResult{Label: o.Label, Kind: o.Kind})
		}
		res.Labels[i].Total++
		if o.Blocked {
			res.Labels[i].Blocked++
		}
		switch o.Kind {
		case scenario.Attack:
			res.AttackTotal++
			if o.Blocked {
				res.AttackBlocked++
			}
		case scenario.Benign:
			res.BenignTotal++
			if o.Blocked {
				res.BenignBlocked++
			}
		}
	}
	if res.AttackTotal > 0 {
		res.DetectionRate = float64(res.AttackBlocked) / float64(res.AttackTotal)
	}
	if res.BenignTotal > 0 {
		res.FalsePositiveRate = float64(res.BenignBlocked) / float64(res.BenignTotal)
	}
	s := 100 * res.DetectionRate * (1 - res.FalsePositiveRate)
	if hintUsed {
		s *= HintMultiplier
	}
	res.Score = int(math.Round(s))
	return res
}
