package score

import (
	"testing"
	"time"

	"wafdy/internal/scenario"
)

func TestCompute(t *testing.T) {
	var outs []Outcome
	for i := 0; i < 10; i++ {
		outs = append(outs, Outcome{Kind: scenario.Attack, Key: "a", Label: scenario.T("攻撃", "attack"), Blocked: i < 8, Scored: true})
	}
	for i := 0; i < 10; i++ {
		outs = append(outs, Outcome{Kind: scenario.Benign, Key: "b", Label: scenario.T("正常", "benign"), Blocked: i < 1, Scored: true})
	}
	outs = append(outs,
		Outcome{Kind: scenario.Attack, Key: "a", Label: scenario.T("攻撃", "attack"), Scored: false},
		Outcome{Kind: scenario.Benign, Key: "b", Label: scenario.T("正常", "benign"), Err: true, Scored: true},
	)

	res := Compute(outs, false)
	if res.AttackTotal != 10 || res.AttackBlocked != 8 || res.BenignTotal != 10 || res.BenignBlocked != 1 || res.Errors != 1 {
		t.Fatalf("unexpected counts: %+v", res)
	}
	if res.Score != 72 { // 100 * 0.8 * 0.9
		t.Fatalf("score = %d, want 72", res.Score)
	}
	if got := Compute(outs, true).Score; got != 58 { // 72 * 0.8
		t.Fatalf("score with hint = %d, want 58", got)
	}
}

func TestPropagationSuspects(t *testing.T) {
	sec := func(n int) time.Duration { return time.Duration(n) * time.Second }
	attack := func(at int, blocked bool) Outcome {
		return Outcome{Kind: scenario.Attack, Key: "a", Blocked: blocked, Scored: true, At: sec(at)}
	}
	benign := func(at int, blocked bool) Outcome {
		return Outcome{Kind: scenario.Benign, Key: "b", Blocked: blocked, Scored: true, At: sec(at)}
	}

	// 開始直後の 1 件だけすり抜け、15 秒以降は全件ブロック → 反映待ちの可能性あり。採点はそのまま
	res := Compute([]Outcome{attack(0, false), attack(3, true), attack(20, true), attack(25, true), benign(5, false)}, false)
	if res.PropagationSuspects != 1 || res.AttackBlocked != 3 || res.AttackTotal != 4 || res.Score != 75 {
		t.Errorf("early leak: suspects=%d blocked=%d/%d score=%d, want 1, 3/4, 75", res.PropagationSuspects, res.AttackBlocked, res.AttackTotal, res.Score)
	}

	// 15 秒以降にもすり抜けがある → 本当の設定ミスなので知らせない
	res = Compute([]Outcome{attack(0, false), attack(20, true), attack(25, false)}, false)
	if res.PropagationSuspects != 0 {
		t.Errorf("real miss: suspects=%d, want 0", res.PropagationSuspects)
	}

	// 15 秒以降の結果がない種類は判断できない
	res = Compute([]Outcome{{Kind: scenario.Attack, Key: "c", Scored: true, At: sec(1)}}, false)
	if res.PropagationSuspects != 0 {
		t.Error("without later evidence there should be no suspects")
	}

	// ルールを外した直後に正常な通信を誤ブロックし、そのあと全件通過 → 反映待ちの可能性あり
	res = Compute([]Outcome{attack(20, true), benign(1, true), benign(18, false), benign(22, false)}, false)
	if res.PropagationSuspects != 1 || res.BenignBlocked != 1 {
		t.Errorf("early false positive: suspects=%d benignBlocked=%d", res.PropagationSuspects, res.BenignBlocked)
	}
}

func TestComputeNoAttack(t *testing.T) {
	if got := Compute(nil, false).Score; got != 0 {
		t.Fatalf("score = %d, want 0", got)
	}
}
