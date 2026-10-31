// Package scenario は学習用シナリオ（チュートリアルとゲームステージ）を定義する。
// 各シナリオは、事前に画面へ出す説明と、トラフィック生成器が送るリクエストの両方を持つ。
package scenario

import (
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	"wafdy/internal/tlsprofile"
	"wafdy/internal/wafrule"
)

type Kind string

const (
	Attack Kind = "attack"
	Benign Kind = "benign"
)

// TutorialClearScore はチュートリアル 1 本をクリアしたとみなすスコア。
// すべてのチュートリアルをクリアするとゲームモードとラボが解放される。
const TutorialClearScore = 70

// MasteryScore はゲームとラボの 1 問を「こなした」とみなすスコア。
// ゲームとラボをすべてこの点数以上にすると WAF スペシャリストに認定される。
const MasteryScore = 80

// TargetCloudFront は、攻撃を ALB ではなくプレイヤーの CloudFront に送るシナリオ。
const TargetCloudFront = "cloudfront"

const (
	CategoryTutorial = "tutorial"
	CategoryGame     = "game"
	CategoryLab      = "lab"
	CategoryExam     = "exam"
	CategoryOps      = "ops"
)

// Request は生成器が送る 1 リクエスト。ClientIP は X-Forwarded-For に入る。
// TLS が空なら User-Agent に合うブラウザの ClientHello で接続する。
type Request struct {
	Method   string
	Path     string
	RawQuery string
	Headers  map[string]string
	Body     string
	ClientIP string
	TLS      tlsprofile.Name
}

func (r Request) TLSProfile() tlsprofile.Name {
	if r.TLS != "" {
		return r.TLS
	}
	return tlsprofile.ForUserAgent(r.Headers["User-Agent"])
}

func (r Request) MethodOrGet() string {
	if r.Method == "" {
		return "GET"
	}
	return r.Method
}

func (r Request) Target() string {
	if r.RawQuery == "" {
		return r.Path
	}
	return r.Path + "?" + r.RawQuery
}

// Pattern は同じラベルを持つリクエスト群。Count 件が Duration の間に均等に送られる。
type Pattern struct {
	Kind  Kind
	Label Text
	Count int
	Make  func(r *rand.Rand) Request
}

type Scenario struct {
	ID       string
	Title    Text
	Tutorial bool
	// Lab は脆弱性対応ラボの問題。Level は 1〜3 (1: 勧告どおり, 2: 勧告を翻訳, 3: PoC から導く)。
	Lab   bool
	Level int
	CVE   string
	// Conditions は「こういう条件で防げるようです」という防ぎ方の情報。
	Conditions []Text
	// Exam は実戦テスト (攻撃の詳細と模範解答を見せない)。Ops は運用演習 (Count で偵察できる)。
	Exam bool
	Ops  bool
	// Recon が true なら、採点しない「偵察」の実行ができる。
	Recon bool
	// HideAttackSamples / HideBenignSamples は、事前に見せるリクエスト例を隠す。
	HideAttackSamples bool
	HideBenignSamples bool
	// Solution は模範解答。複数のルールを組み合わせる場合は SolutionACL に優先度順に並べる。
	// HideSolution なら模範解答は画面に出さず、テストでの確認にだけ使う。
	// Pitfall はありがちな失敗例（すり抜けや誤検知が起きる）。
	Solution     *wafrule.Rule
	SolutionACL  []*wafrule.Rule
	HideSolution bool
	// Target は攻撃の送り先。空なら ALB、TargetCloudFront なら CloudFront。
	Target string
	// SolutionBodyLimitKB / PitfallBodyLimitKB は、模範解答と失敗例で Web ACL に設定する
	// Body の検査上限 (CloudFront のみ。0 なら既定の 16 KB)。
	SolutionBodyLimitKB int
	PitfallBodyLimitKB  int
	SolutionNote        []Text
	Pitfall             *wafrule.Rule
	PitfallNote         []Text
	Summary             Text
	Topics              []Text
	Briefing            []Text
	// Lesson は新しい概念の解説（チュートリアル用）。
	Lesson []Text
	// ShowJA4 が true なら、リクエスト例に JA4 を添えて表示する。
	ShowJA4     bool
	Steps       []Step
	Hints       []Text
	PrepSeconds int
	Duration    time.Duration
	// Warmup より前に送った攻撃は採点しない（レートベースルールの立ち上がり待ち）。
	Warmup   time.Duration
	Patterns []Pattern
}

// Step はチュートリアルの手順 1 つ。Detail は画面で折りたたんで見せる、設定項目の補足説明 (任意)。
type Step struct {
	Do     Text
	Detail []Text
}

// S は手順を作る。detail を渡すと、画面に「くわしい説明」の折りたたみが付く。
func S(do Text, detail ...Text) Step { return Step{Do: do, Detail: detail} }

type StepView struct {
	Text   string   `json:"text"`
	Detail []string `json:"detail,omitempty"`
}

func stepsIn(steps []Step, l Lang) []StepView {
	if len(steps) == 0 {
		return nil
	}
	out := make([]StepView, len(steps))
	for i, st := range steps {
		out[i] = StepView{Text: st.Do.In(l), Detail: in(st.Detail, l)}
	}
	return out
}

type Sample struct {
	Kind  Kind   `json:"kind"`
	Label string `json:"label"`
	Raw   string `json:"raw"`
}

func (s *Scenario) Category() string {
	switch {
	case s.Tutorial:
		return CategoryTutorial
	case s.Lab:
		return CategoryLab
	case s.Exam:
		return CategoryExam
	case s.Ops:
		return CategoryOps
	}
	return CategoryGame
}

// HasReference は、テストで確かめられる模範解答があるか。
func (s *Scenario) HasReference() bool { return s.Solution != nil || len(s.SolutionACL) > 0 }

// bodyLimit は、Web ACL に設定した上限 (KB) から、WAF が検査できる Body の大きさを返す。
func (s *Scenario) bodyLimit(kb int) int {
	switch {
	case s.Target != TargetCloudFront:
		return wafrule.BodyInspectionLimit // ALB は 8 KB で固定
	case kb == 0:
		return wafrule.CloudFrontDefaultBodyLimit
	}
	return kb * 1024
}

// ReferenceBlocks は、模範解答を入れた Web ACL がこのリクエストをブロックするかを返す。
func (s *Scenario) ReferenceBlocks(req Request) (bool, error) {
	view := req.WAFView()
	view.BodyLimit = s.bodyLimit(s.SolutionBodyLimitKB)
	if len(s.SolutionACL) > 0 {
		return wafrule.EvaluateACL(s.SolutionACL, view)
	}
	return s.Solution.Matches(view)
}

// PitfallBlocks は、失敗例のルールを入れた Web ACL がこのリクエストをブロックするかを返す。
func (s *Scenario) PitfallBlocks(req Request) (bool, error) {
	view := req.WAFView()
	view.BodyLimit = s.bodyLimit(s.PitfallBodyLimitKB)
	return s.Pitfall.Matches(view)
}

// View は画面に返す公開情報。文章は 1 つの言語に絞って返す。模範解答は含めない。
type View struct {
	Lang        Lang       `json:"lang"`
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Category    string     `json:"category"`
	Level       int        `json:"level,omitempty"`
	CVE         string     `json:"cve,omitempty"`
	Conditions  []string   `json:"conditions,omitempty"`
	HasSolution bool       `json:"hasSolution"`
	Target      string     `json:"target,omitempty"`
	Recon       bool       `json:"recon,omitempty"`
	Tutorial    bool       `json:"tutorial"`
	Summary     string     `json:"summary"`
	Topics      []string   `json:"topics"`
	Briefing    []string   `json:"briefing"`
	Lesson      []string   `json:"lesson,omitempty"`
	Steps       []StepView `json:"steps,omitempty"`
	Hints       []string   `json:"hints,omitempty"`
	PrepSeconds int        `json:"prepSeconds"`
	DurationSec int        `json:"durationSec"`
	AttackCount int        `json:"attackCount"`
	BenignCount int        `json:"benignCount"`
	Samples     []Sample   `json:"samples"`
}

func (s *Scenario) View(l Lang) View {
	v := View{
		Lang:        l,
		ID:          s.ID,
		Title:       s.Title.In(l),
		Category:    s.Category(),
		Level:       s.Level,
		CVE:         s.CVE,
		Conditions:  in(s.Conditions, l),
		HasSolution: s.HasReference() && !s.HideSolution,
		Target:      s.Target,
		Recon:       s.Recon,
		Tutorial:    s.Tutorial,
		Summary:     s.Summary.In(l),
		Topics:      in(s.Topics, l),
		Briefing:    in(s.Briefing, l),
		Lesson:      in(s.Lesson, l),
		Steps:       stepsIn(s.Steps, l),
		Hints:       in(s.Hints, l),
		PrepSeconds: s.PrepSeconds,
		DurationSec: int(s.Duration.Seconds()),
	}
	// チュートリアルは全種類の攻撃例を見せ、ゲームでは「予兆」として 1 種類だけ見せる。
	rng := rand.New(rand.NewPCG(1, 2))
	sample := func(p Pattern) Sample {
		req := p.Make(rng)
		raw := FormatRequest(req)
		if s.ShowJA4 {
			raw = T("# TLS フィンガープリント (JA4): ", "# TLS fingerprint (JA4): ").In(l) + tlsprofile.JA4(req.TLSProfile()) + "\n" + raw
		}
		return Sample{p.Kind, p.Label.In(l), raw}
	}
	shownAttack, shownBenign := 0, 0
	for _, p := range s.Patterns {
		switch p.Kind {
		case Attack:
			v.AttackCount += p.Count
			if !s.HideAttackSamples && (s.Tutorial || shownAttack == 0) {
				v.Samples = append(v.Samples, sample(p))
				shownAttack++
			}
		case Benign:
			v.BenignCount += p.Count
			if !s.HideBenignSamples && shownBenign == 0 {
				v.Samples = append(v.Samples, sample(p))
				shownBenign++
			}
		}
	}
	return v
}

// SolutionView は模範解答。挑戦したプレイヤーにだけ返す。
type SolutionView struct {
	Rule string `json:"rule"`
	// ACLConfig は、ルールのほかに Web ACL 自体に設定する内容 (JSON)。
	ACLConfig   string   `json:"aclConfig,omitempty"`
	Notes       []string `json:"notes"`
	Pitfall     string   `json:"pitfall,omitempty"`
	PitfallNote []string `json:"pitfallNote,omitempty"`
}

func (s *Scenario) SolutionView(l Lang) *SolutionView {
	if !s.HasReference() || s.HideSolution {
		return nil
	}
	v := &SolutionView{Notes: in(s.SolutionNote, l), PitfallNote: in(s.PitfallNote, l)}
	if len(s.SolutionACL) > 0 {
		v.Rule = wafrule.ACLJSON(s.SolutionACL)
	} else {
		v.Rule = s.Solution.JSON()
	}
	if s.Target == TargetCloudFront && s.SolutionBodyLimitKB > 0 {
		v.ACLConfig = fmt.Sprintf(`{
  "AssociationConfig": {
    "RequestBody": {
      "CLOUDFRONT": {
        "DefaultSizeInspectionLimit": "KB_%d"
      }
    }
  }
}`, s.SolutionBodyLimitKB)
	}
	if s.Pitfall != nil {
		v.Pitfall = s.Pitfall.JSON()
	}
	return v
}

// WAFView は、このリクエストが AWS WAF からどう見えるかを返す（模範解答のテスト用）。
// ヘッダーは生成器 (Go の HTTP クライアント) が実際に付けるものも含める。
func (r Request) WAFView() wafrule.Request {
	w := wafrule.Request{Method: r.MethodOrGet(), Path: r.Path, RawQuery: r.RawQuery, Body: r.Body, JA4: tlsprofile.JA4(r.TLSProfile())}
	w.Headers = append(w.Headers, [2]string{"Host", "shop.wafdojo.example"})
	keys := make([]string, 0, len(r.Headers))
	for k := range r.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		// 値が空のヘッダーは送られない (Go の HTTP クライアントは空の User-Agent を送らない)
		if r.Headers[k] != "" {
			w.Headers = append(w.Headers, [2]string{k, r.Headers[k]})
		}
	}
	if r.Body != "" {
		w.Headers = append(w.Headers, [2]string{"Content-Length", fmt.Sprint(len(r.Body))})
	}
	w.Headers = append(w.Headers, [2]string{"X-Forwarded-For", r.ClientIP}, [2]string{"Accept-Encoding", "gzip"})
	return w
}

// FormatRequest はリクエストを生の HTTP 形式の文字列にする。
func FormatRequest(req Request) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\n", req.MethodOrGet(), req.Target())
	b.WriteString("Host: <your-alb>\n")
	keys := make([]string, 0, len(req.Headers))
	for k := range req.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if req.Headers[k] != "" {
			fmt.Fprintf(&b, "%s: %s\n", k, req.Headers[k])
		}
	}
	if req.ClientIP != "" {
		fmt.Fprintf(&b, "X-Forwarded-For: %s\n", req.ClientIP)
	}
	if req.Body != "" {
		b.WriteString("\n" + req.Body + "\n")
	}
	return b.String()
}

var registry = map[string]*Scenario{}
var ordered []*Scenario

func register(s *Scenario) {
	registry[s.ID] = s
	ordered = append(ordered, s)
}

func Get(id string) (*Scenario, bool) {
	s, ok := registry[id]
	return s, ok
}

func All() []*Scenario {
	return ordered
}

func byCategory(c string) []*Scenario {
	var out []*Scenario
	for _, s := range ordered {
		if s.Category() == c {
			out = append(out, s)
		}
	}
	return out
}

// Games はゲームモードのステージ一覧。
func Games() []*Scenario { return byCategory(CategoryGame) }

// Labs は脆弱性対応ラボの問題一覧。
func Labs() []*Scenario { return byCategory(CategoryLab) }

// Exams は実戦テスト、OpsDrills は運用演習の一覧。
func Exams() []*Scenario     { return byCategory(CategoryExam) }
func OpsDrills() []*Scenario { return byCategory(CategoryOps) }

// Masterable は「こなす」対象 (チュートリアル以外) の一覧。
func Masterable() []*Scenario {
	var out []*Scenario
	for _, s := range ordered {
		if !s.Tutorial {
			out = append(out, s)
		}
	}
	return out
}

// Tutorials はゲームモード解放の条件になるチュートリアルの一覧。
func Tutorials() []*Scenario {
	var ts []*Scenario
	for _, s := range ordered {
		if s.Tutorial {
			ts = append(ts, s)
		}
	}
	return ts
}
