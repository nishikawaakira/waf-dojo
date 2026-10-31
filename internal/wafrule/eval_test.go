package wafrule

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTransforms(t *testing.T) {
	cases := []struct {
		in    string
		types []string
		want  string
	}{
		{"%2e%2e%2f", []string{URLDecode}, "../"},
		{"%252e%252e%252f", []string{URLDecode}, "%2e%2e%2f"},
		{"%252e%252e%252f", []string{URLDecode, URLDecode}, "../"},
		{"%zz+a", []string{URLDecode}, "%zz a"},
		{"/a//b/./c/../d/", []string{NormalizePath}, "/a/b/d/"},
		{"/vpn/../vpns/x", []string{NormalizePath}, "/vpns/x"},
		{"../../etc", []string{NormalizePath}, "../../etc"},
		{`\a\..\b`, []string{NormalizePathWin}, "/b"},
		{`"\u005f\u005fproto\u005f\u005f"`, []string{JSDecode}, `"__proto__"`},
		{"a \t\n b", []string{CompressWhiteSpace}, "a b"},
		{"&lt;script&gt;", []string{HTMLEntityDecode, Lowercase}, "<script>"},
	}
	for _, c := range cases {
		got, err := transform(c.in, transforms(c.types))
		if err != nil || got != c.want {
			t.Errorf("transform(%q, %v) = %q, %v; want %q", c.in, c.types, got, err, c.want)
		}
	}
}

func TestEval(t *testing.T) {
	req := Request{
		Method:   "GET",
		Path:     "/Admin/Users",
		RawQuery: "lang=en&next=..%2fhelp",
		Headers:  [][2]string{{"User-Agent", "Mozilla"}, {"X-Test", "() { :; };"}},
	}
	cases := []struct {
		name string
		s    *Statement
		want bool
	}{
		{"starts with + lowercase", StartsWith("/admin/", UriPath(), Lowercase), true},
		{"starts with, no transform", StartsWith("/admin/", UriPath()), false},
		{"single query arg", Contains("../", QueryArg("next"), URLDecode), true},
		{"other query arg", Contains("../", QueryArg("lang"), URLDecode), false},
		{"all header values", Contains("() {", AllHeaderValues()), true},
		{"header present", Present(Header("x-test")), true},
		{"missing header is no match", Present(Header("x-missing")), false},
		{"not missing header", Not(Present(Header("x-missing"))), true},
		{"and/or", And(Contains("/admin", UriPath(), Lowercase), Or(Exactly("POST", Method()), Exactly("GET", Method()))), true},
		{"regex", Regex(`^/[A-Z]`, UriPath()), true},
	}
	for _, c := range cases {
		got, err := Block("t", c.s).Matches(req)
		if err != nil || got != c.want {
			t.Errorf("%s: got %v, %v; want %v", c.name, got, err, c.want)
		}
	}
}

func TestJSONShape(t *testing.T) {
	r := Block("block-x", And(Contains("${", UriPath(), URLDecode), Not(Present(Header("x-a")))))
	var m map[string]any
	if err := json.Unmarshal([]byte(r.JSON()), &m); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"AndStatement"`, `"NotStatement"`, `"UriPath": {}`, `"Block": {}`, `"PositionalConstraint": "CONTAINS"`} {
		if !strings.Contains(r.JSON(), want) {
			t.Errorf("JSON missing %s:\n%s", want, r.JSON())
		}
	}
}

func TestManagedGroupWithLabelException(t *testing.T) {
	big := strings.Repeat("a", 9000)
	acl := []*Rule{
		ManagedGroup("AWSManagedRulesCommonRuleSet", "SizeRestrictions_BODY"),
		Block("block-big-bodies-except-upload", And(
			Label(CoreRuleSetLabel+"SizeRestrictions_Body"),
			Not(StartsWith("/upload", UriPath())),
		)),
	}
	ua := [2]string{"User-Agent", "Mozilla"}
	cases := []struct {
		name string
		req  Request
		want bool
	}{
		{"big upload is allowed", Request{Path: "/upload", Body: big, Headers: [][2]string{ua}}, false},
		{"big body elsewhere is blocked by the label rule", Request{Path: "/comment", Body: big, Headers: [][2]string{ua}}, true},
		{"xss is still blocked by the group", Request{Path: "/upload", Body: "x=<script>alert(1)</script>", Headers: [][2]string{ua}}, true},
		{"missing user agent is blocked by the group", Request{Path: "/"}, true},
		{"normal request passes", Request{Path: "/", Headers: [][2]string{ua}}, false},
	}
	for _, c := range cases {
		got, err := EvaluateACL(acl, c.req)
		if err != nil || got != c.want {
			t.Errorf("%s: got %v, %v; want %v", c.name, got, err, c.want)
		}
	}
	// ラベルのルールが先に評価されるとラベルがまだないので、順番を逆にするとすり抜ける
	if got, _ := EvaluateACL([]*Rule{acl[1], acl[0]}, cases[1].req); got != false {
		t.Error("label rule placed before the managed group should not see the label")
	}
	if !strings.Contains(ACLJSON(acl), `"OverrideAction": {`) || !strings.Contains(ACLJSON(acl), `"Count": {}`) {
		t.Errorf("unexpected ACL JSON:\n%s", ACLJSON(acl))
	}
}

func TestBodyInspectionLimit(t *testing.T) {
	hidden := Request{Path: "/comment", Body: strings.Repeat("a", BodyInspectionLimit+100) + "<script>"}
	small := Request{Path: "/comment", Body: "x=<script>"}
	big := Request{Path: "/upload", Body: strings.Repeat("a", BodyInspectionLimit+100)}
	cases := []struct {
		name     string
		handling string
		req      Request
		want     bool
	}{
		{"CONTINUE only sees the first 8 KB, so the hidden script slips through", "CONTINUE", hidden, false},
		{"MATCH treats any oversized body as a match", "MATCH", hidden, true},
		{"MATCH also catches oversized bodies without a script", "MATCH", big, true},
		{"NO_MATCH never matches oversized bodies", "NO_MATCH", hidden, false},
		{"small bodies are inspected normally", "CONTINUE", small, true},
	}
	for _, c := range cases {
		got, err := Block("t", Contains("<script>", BodyFieldOversize(c.handling))).Matches(c.req)
		if err != nil || got != c.want {
			t.Errorf("%s: got %v, %v; want %v", c.name, got, err, c.want)
		}
	}
}

func TestCloudFrontBodyLimit(t *testing.T) {
	// 20 KB の後ろに隠した script: ALB (8 KB) と CloudFront 既定 (16 KB) では見えず、64 KB にすれば見える
	req := Request{Path: "/api/reports", Body: strings.Repeat("a", 20*1024) + "<script>"}
	rule := Block("t", Contains("<script>", BodyFieldOversize("CONTINUE")))
	for _, c := range []struct {
		limit int
		want  bool
	}{{0, false}, {CloudFrontDefaultBodyLimit, false}, {CloudFrontMaxBodyLimit, true}} {
		req.BodyLimit = c.limit
		if got, _ := rule.Matches(req); got != c.want {
			t.Errorf("limit %d: got %v, want %v", c.limit, got, c.want)
		}
	}
}
