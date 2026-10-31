package wafrule

import (
	"fmt"
	"regexp"
	"strings"
)

// マネージドルールグループの一部のルールを、AWS のドキュメントに書かれた動きに沿って再現する。
// 中身は非公開なので完全な再現ではない。問題の通信は、ここで再現したルールに確実に当たる
// (または当たらない) ものだけを使う。

type managedRule struct {
	name  string // RuleActionOverrides で指定する名前
	label string // 一致したときに付くラベル (接頭辞を除く)
	match func(Request) bool
}

var (
	rfiPattern = regexp.MustCompile(`(?i)https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	xssPattern = regexp.MustCompile(`(?i)<\s*script|\bon(error|load|click|mouseover)\s*=|javascript:`)
)

func header(req Request, name string) (string, bool) {
	for _, h := range req.Headers {
		if strings.EqualFold(h[0], name) {
			return h[1], true
		}
	}
	return "", false
}

func queryValues(req Request) []string {
	var out []string
	for _, kv := range strings.Split(req.RawQuery, "&") {
		_, v, _ := strings.Cut(kv, "=")
		out = append(out, urlDecode(v))
	}
	return out
}

var managedGroups = map[string][]managedRule{
	"AWSManagedRulesCommonRuleSet": {
		{"NoUserAgent_HEADER", "NoUserAgent_Header", func(r Request) bool {
			ua, ok := header(r, "user-agent")
			return !ok || ua == ""
		}},
		{"SizeRestrictions_QUERYSTRING", "SizeRestrictions_QueryString", func(r Request) bool { return len(r.RawQuery) > 2048 }},
		{"SizeRestrictions_BODY", "SizeRestrictions_Body", func(r Request) bool { return len(r.Body) > 8192 }},
		{"GenericLFI_QUERYARGUMENTS", "GenericLFI_QueryArguments", func(r Request) bool {
			for _, v := range queryValues(r) {
				if strings.Contains(v, "../") {
					return true
				}
			}
			return false
		}},
		{"GenericRFI_QUERYARGUMENTS", "GenericRFI_QueryArguments", func(r Request) bool {
			for _, v := range queryValues(r) {
				if rfiPattern.MatchString(v) {
					return true
				}
			}
			return false
		}},
		{"CrossSiteScripting_BODY", "CrossSiteScripting_Body", func(r Request) bool {
			body := r.Body
			if len(body) > r.bodyLimit() {
				body = body[:r.bodyLimit()] // マネージドルールも先頭しか検査できない
			}
			return xssPattern.MatchString(urlDecode(body))
		}},
	},
}

// evalManaged はマネージドルールグループを評価する。一致したルールのラベルを labels に足し、
// Count に上書きされていないルールに一致したら true (Block) を返す。
func evalManaged(m *ManagedRuleGroupStatement, req Request, labels map[string]bool) (bool, error) {
	rules, ok := managedGroups[m.Name]
	if !ok || m.VendorName != "AWS" {
		return false, fmt.Errorf("managed rule group %s/%s is not emulated", m.VendorName, m.Name)
	}
	counted := map[string]bool{}
	for _, o := range m.RuleActionOverrides {
		if o.ActionToUse.Count != nil {
			counted[o.Name] = true
		}
	}
	prefix := ""
	if m.Name == "AWSManagedRulesCommonRuleSet" {
		prefix = CoreRuleSetLabel
	}
	for _, r := range rules {
		if !r.match(req) {
			continue
		}
		labels[prefix+r.label] = true
		if !counted[r.name] {
			return true, nil
		}
	}
	return false, nil
}

// EvaluateACL は Web ACL のルールを並び順 (= 優先度順) に評価し、ブロックされるかを返す。
// 既定のアクションは Allow とする。
func EvaluateACL(rules []*Rule, req Request) (bool, error) {
	labels := map[string]bool{}
	req.labels = labels
	for _, r := range rules {
		if m := r.Statement.ManagedRuleGroupStatement; m != nil {
			blocked, err := evalManaged(m, req, labels)
			if err != nil || blocked {
				return blocked, err
			}
			continue
		}
		ok, err := r.Statement.matches(req)
		if err != nil {
			return false, err
		}
		if !ok || r.Action == nil {
			continue
		}
		switch {
		case r.Action.Block != nil:
			return true, nil
		case r.Action.Allow != nil:
			return false, nil
		}
	}
	return false, nil
}
