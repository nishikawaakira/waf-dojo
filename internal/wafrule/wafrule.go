// Package wafrule は AWS WAF のルールを、コンソールの「Rule JSON editor」と同じ JSON 形式で表し、
// その一部の機能をローカルで評価する。
//
// 脆弱性対応ラボの模範解答をこの型で書き、
//   - 画面にそのまま貼り付けられる JSON として表示する
//   - テストで「模範解答が攻撃をすべて止め、正常な通信を止めない」ことを確かめる
//
// の 2 つに使う。評価器は模範解答で使う範囲だけを実装しており、AWS WAF の完全な再現ではない。
package wafrule

import "encoding/json"

type Rule struct {
	Name      string     `json:"Name"`
	Priority  int        `json:"Priority"`
	Statement *Statement `json:"Statement"`
	// 通常のルールは Action、マネージドルールグループは OverrideAction を持つ。
	Action           *Action          `json:"Action,omitempty"`
	OverrideAction   *OverrideAction  `json:"OverrideAction,omitempty"`
	VisibilityConfig VisibilityConfig `json:"VisibilityConfig"`
}

type Action struct {
	Block *empty `json:"Block,omitempty"`
	Count *empty `json:"Count,omitempty"`
	Allow *empty `json:"Allow,omitempty"`
}

type OverrideAction struct {
	None *empty `json:"None"`
}

type VisibilityConfig struct {
	SampledRequestsEnabled   bool   `json:"SampledRequestsEnabled"`
	CloudWatchMetricsEnabled bool   `json:"CloudWatchMetricsEnabled"`
	MetricName               string `json:"MetricName"`
}

type Statement struct {
	ByteMatchStatement      *ByteMatchStatement      `json:"ByteMatchStatement,omitempty"`
	RegexMatchStatement     *RegexMatchStatement     `json:"RegexMatchStatement,omitempty"`
	SizeConstraintStatement *SizeConstraintStatement `json:"SizeConstraintStatement,omitempty"`
	AndStatement            *AndStatement            `json:"AndStatement,omitempty"`
	OrStatement             *OrStatement             `json:"OrStatement,omitempty"`
	NotStatement            *NotStatement            `json:"NotStatement,omitempty"`
	LabelMatchStatement     *LabelMatchStatement     `json:"LabelMatchStatement,omitempty"`
	// ManagedRuleGroupStatement はルールの最上位でだけ使う。
	ManagedRuleGroupStatement *ManagedRuleGroupStatement `json:"ManagedRuleGroupStatement,omitempty"`
}

type LabelMatchStatement struct {
	Scope string `json:"Scope"`
	Key   string `json:"Key"`
}

type ManagedRuleGroupStatement struct {
	VendorName          string               `json:"VendorName"`
	Name                string               `json:"Name"`
	RuleActionOverrides []RuleActionOverride `json:"RuleActionOverrides,omitempty"`
}

type RuleActionOverride struct {
	Name        string `json:"Name"`
	ActionToUse Action `json:"ActionToUse"`
}

type ByteMatchStatement struct {
	SearchString         string               `json:"SearchString"`
	FieldToMatch         FieldToMatch         `json:"FieldToMatch"`
	TextTransformations  []TextTransformation `json:"TextTransformations"`
	PositionalConstraint string               `json:"PositionalConstraint"`
}

type RegexMatchStatement struct {
	RegexString         string               `json:"RegexString"`
	FieldToMatch        FieldToMatch         `json:"FieldToMatch"`
	TextTransformations []TextTransformation `json:"TextTransformations"`
}

type SizeConstraintStatement struct {
	FieldToMatch        FieldToMatch         `json:"FieldToMatch"`
	ComparisonOperator  string               `json:"ComparisonOperator"`
	Size                int64                `json:"Size"`
	TextTransformations []TextTransformation `json:"TextTransformations"`
}

type AndStatement struct {
	Statements []*Statement `json:"Statements"`
}

type OrStatement struct {
	Statements []*Statement `json:"Statements"`
}

type NotStatement struct {
	Statement *Statement `json:"Statement"`
}

type TextTransformation struct {
	Priority int    `json:"Priority"`
	Type     string `json:"Type"`
}

type empty struct{}

type FieldToMatch struct {
	UriPath             *empty          `json:"UriPath,omitempty"`
	QueryString         *empty          `json:"QueryString,omitempty"`
	Method              *empty          `json:"Method,omitempty"`
	SingleHeader        *Named          `json:"SingleHeader,omitempty"`
	SingleQueryArgument *Named          `json:"SingleQueryArgument,omitempty"`
	Body                *Body           `json:"Body,omitempty"`
	Headers             *Headers        `json:"Headers,omitempty"`
	JA4Fingerprint      *JA4Fingerprint `json:"JA4Fingerprint,omitempty"`
}

type Named struct {
	Name string `json:"Name"`
}

type Body struct {
	OversizeHandling string `json:"OversizeHandling"`
}

type Headers struct {
	MatchPattern     HeaderMatchPattern `json:"MatchPattern"`
	MatchScope       string             `json:"MatchScope"`
	OversizeHandling string             `json:"OversizeHandling"`
}

type HeaderMatchPattern struct {
	All *empty `json:"All,omitempty"`
}

type JA4Fingerprint struct {
	FallbackBehavior string `json:"FallbackBehavior"`
}

// JSON はコンソールの Rule JSON editor に貼り付けられる形の JSON を返す。
func (r Rule) JSON() string {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(b)
}

// ---------- ルールを組み立てる関数 ----------

func visibility(name string) VisibilityConfig {
	return VisibilityConfig{SampledRequestsEnabled: true, CloudWatchMetricsEnabled: true, MetricName: name}
}

// Block は Block アクションのルールを作る。
func Block(name string, s *Statement) *Rule {
	return &Rule{Name: name, Statement: s, Action: &Action{Block: &empty{}}, VisibilityConfig: visibility(name)}
}

// ManagedGroup は AWS マネージドルールグループのルールを作る。countRules に挙げたルールは
// Block ではなく Count にする (ラベルだけ付けて、判定は後ろのルールに任せる)。
func ManagedGroup(groupName string, countRules ...string) *Rule {
	m := &ManagedRuleGroupStatement{VendorName: "AWS", Name: groupName}
	for _, r := range countRules {
		m.RuleActionOverrides = append(m.RuleActionOverrides, RuleActionOverride{Name: r, ActionToUse: Action{Count: &empty{}}})
	}
	name := "AWS-" + groupName
	return &Rule{Name: name, Statement: &Statement{ManagedRuleGroupStatement: m}, OverrideAction: &OverrideAction{None: &empty{}}, VisibilityConfig: visibility(name)}
}

// Label は、前に評価されたルールが付けたラベルに一致するステートメント。
func Label(key string) *Statement {
	return &Statement{LabelMatchStatement: &LabelMatchStatement{Scope: "LABEL", Key: key}}
}

// ACLJSON は複数のルールを、優先度を振り直して JSON の配列にする。
func ACLJSON(rules []*Rule) string {
	out := make([]Rule, len(rules))
	for i, r := range rules {
		out[i] = *r
		out[i].Priority = i
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(b)
}

// テキスト変換の種類。
const (
	None               = "NONE"
	URLDecode          = "URL_DECODE"
	Lowercase          = "LOWERCASE"
	CompressWhiteSpace = "COMPRESS_WHITE_SPACE"
	HTMLEntityDecode   = "HTML_ENTITY_DECODE"
	JSDecode           = "JS_DECODE"
	NormalizePath      = "NORMALIZE_PATH"
	NormalizePathWin   = "NORMALIZE_PATH_WIN"
)

// AWSManagedRulesCommonRuleSet (Core rule set) が付けるラベルの接頭辞。
const CoreRuleSetLabel = "awswaf:managed:aws:core-rule-set:"

func transforms(types []string) []TextTransformation {
	if len(types) == 0 {
		types = []string{None}
	}
	out := make([]TextTransformation, len(types))
	for i, t := range types {
		out[i] = TextTransformation{Priority: i, Type: t}
	}
	return out
}

func byteMatch(pos, s string, f FieldToMatch, t []string) *Statement {
	return &Statement{ByteMatchStatement: &ByteMatchStatement{SearchString: s, FieldToMatch: f, TextTransformations: transforms(t), PositionalConstraint: pos}}
}

func Contains(s string, f FieldToMatch, t ...string) *Statement {
	return byteMatch("CONTAINS", s, f, t)
}
func StartsWith(s string, f FieldToMatch, t ...string) *Statement {
	return byteMatch("STARTS_WITH", s, f, t)
}
func Exactly(s string, f FieldToMatch, t ...string) *Statement { return byteMatch("EXACTLY", s, f, t) }
func EndsWith(s string, f FieldToMatch, t ...string) *Statement {
	return byteMatch("ENDS_WITH", s, f, t)
}

func Regex(re string, f FieldToMatch, t ...string) *Statement {
	return &Statement{RegexMatchStatement: &RegexMatchStatement{RegexString: re, FieldToMatch: f, TextTransformations: transforms(t)}}
}

// Present は「そのフィールドが空でない (= ヘッダーなどが付いている)」ことを表す。
func Present(f FieldToMatch) *Statement {
	return &Statement{SizeConstraintStatement: &SizeConstraintStatement{FieldToMatch: f, ComparisonOperator: "GT", Size: 0, TextTransformations: transforms(nil)}}
}

func And(s ...*Statement) *Statement { return &Statement{AndStatement: &AndStatement{Statements: s}} }
func Or(s ...*Statement) *Statement  { return &Statement{OrStatement: &OrStatement{Statements: s}} }
func Not(s *Statement) *Statement    { return &Statement{NotStatement: &NotStatement{Statement: s}} }

func UriPath() FieldToMatch           { return FieldToMatch{UriPath: &empty{}} }
func QueryString() FieldToMatch       { return FieldToMatch{QueryString: &empty{}} }
func Method() FieldToMatch            { return FieldToMatch{Method: &empty{}} }
func Header(name string) FieldToMatch { return FieldToMatch{SingleHeader: &Named{Name: name}} }
func QueryArg(name string) FieldToMatch {
	return FieldToMatch{SingleQueryArgument: &Named{Name: name}}
}
func BodyField() FieldToMatch { return FieldToMatch{Body: &Body{OversizeHandling: "CONTINUE"}} }

// JA4 は JA4 フィンガープリントを検査対象にする (取得できなければ一致しない)。
func JA4() FieldToMatch {
	return FieldToMatch{JA4Fingerprint: &JA4Fingerprint{FallbackBehavior: "NO_MATCH"}}
}

// AllHeaderValues はすべてのヘッダーの値を検査対象にする。
func AllHeaderValues() FieldToMatch {
	return FieldToMatch{Headers: &Headers{MatchPattern: HeaderMatchPattern{All: &empty{}}, MatchScope: "VALUE", OversizeHandling: "CONTINUE"}}
}

// AllHeaderKeys はすべてのヘッダーの名前を検査対象にする。
func AllHeaderKeys() FieldToMatch {
	return FieldToMatch{Headers: &Headers{MatchPattern: HeaderMatchPattern{All: &empty{}}, MatchScope: "KEY", OversizeHandling: "CONTINUE"}}
}
