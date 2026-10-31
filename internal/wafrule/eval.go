package wafrule

import (
	"fmt"
	"html"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Request は WAF から見たリクエスト。Path と RawQuery はエンコードされたまま。
type Request struct {
	Method   string
	Path     string
	RawQuery string
	Headers  [][2]string // 名前と値（送った順）
	Body     string
	JA4      string
	// BodyLimit は WAF が検査できる Body の大きさ。0 なら ALB の 8 KB。
	BodyLimit int

	labels map[string]bool // Web ACL の評価中に、前のルールが付けたラベル
}

func (r Request) bodyLimit() int {
	if r.BodyLimit > 0 {
		return r.BodyLimit
	}
	return BodyInspectionLimit
}

// Matches はルールを 1 つだけ入れた Web ACL でブロックされるかを返す。
func (r *Rule) Matches(req Request) (bool, error) {
	return EvaluateACL([]*Rule{r}, req)
}

func (s *Statement) matches(req Request) (bool, error) {
	switch {
	case s.ByteMatchStatement != nil:
		m := s.ByteMatchStatement
		return anyValue(req, m.FieldToMatch, m.TextTransformations, func(v string) (bool, error) {
			return positional(m.PositionalConstraint, v, m.SearchString)
		})
	case s.RegexMatchStatement != nil:
		m := s.RegexMatchStatement
		re, err := regexp.Compile(m.RegexString)
		if err != nil {
			return false, err
		}
		return anyValue(req, m.FieldToMatch, m.TextTransformations, func(v string) (bool, error) {
			return re.MatchString(v), nil
		})
	case s.SizeConstraintStatement != nil:
		m := s.SizeConstraintStatement
		return anyValue(req, m.FieldToMatch, m.TextTransformations, func(v string) (bool, error) {
			return compare(m.ComparisonOperator, int64(len(v)), m.Size)
		})
	case s.AndStatement != nil:
		for _, c := range s.AndStatement.Statements {
			ok, err := c.matches(req)
			if err != nil || !ok {
				return false, err
			}
		}
		return true, nil
	case s.OrStatement != nil:
		for _, c := range s.OrStatement.Statements {
			ok, err := c.matches(req)
			if err != nil || ok {
				return ok, err
			}
		}
		return false, nil
	case s.NotStatement != nil:
		ok, err := s.NotStatement.Statement.matches(req)
		return !ok, err
	case s.LabelMatchStatement != nil:
		l := s.LabelMatchStatement
		if l.Scope == "NAMESPACE" {
			for k := range req.labels {
				if strings.HasPrefix(k, l.Key) {
					return true, nil
				}
			}
			return false, nil
		}
		return req.labels[l.Key], nil
	}
	return false, fmt.Errorf("unsupported statement")
}

// anyValue はフィールドから値を取り出し、変換をかけてから、どれか 1 つでも一致すれば true を返す。
// ヘッダーやクエリパラメータが存在しない場合は一致しない。
func anyValue(req Request, f FieldToMatch, tt []TextTransformation, match func(string) (bool, error)) (bool, error) {
	// Body が検査の上限を超えたら、Oversize handling に従う (CONTINUE なら先頭だけを検査する)
	if f.Body != nil && len(req.Body) > req.bodyLimit() {
		switch f.Body.OversizeHandling {
		case "MATCH":
			return true, nil
		case "NO_MATCH":
			return false, nil
		}
	}
	values, err := extract(req, f)
	if err != nil {
		return false, err
	}
	for _, v := range values {
		v, err := transform(v, tt)
		if err != nil {
			return false, err
		}
		ok, err := match(v)
		if err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

func extract(req Request, f FieldToMatch) ([]string, error) {
	switch {
	case f.UriPath != nil:
		return []string{req.Path}, nil
	case f.QueryString != nil:
		return []string{req.RawQuery}, nil
	case f.Method != nil:
		return []string{req.Method}, nil
	case f.Body != nil:
		body := req.Body
		if len(body) > req.bodyLimit() {
			body = body[:req.bodyLimit()] // WAF には先頭しか渡されない
		}
		return []string{body}, nil
	case f.JA4Fingerprint != nil:
		if req.JA4 == "" {
			return nil, nil
		}
		return []string{req.JA4}, nil
	case f.SingleHeader != nil:
		var out []string
		for _, h := range req.Headers {
			if strings.EqualFold(h[0], f.SingleHeader.Name) {
				out = append(out, h[1])
			}
		}
		return out, nil
	case f.SingleQueryArgument != nil:
		var out []string
		for _, kv := range strings.Split(req.RawQuery, "&") {
			k, v, _ := strings.Cut(kv, "=")
			if strings.EqualFold(k, f.SingleQueryArgument.Name) {
				out = append(out, v)
			}
		}
		return out, nil
	case f.Headers != nil:
		var out []string
		for _, h := range req.Headers {
			switch f.Headers.MatchScope {
			case "KEY":
				out = append(out, h[0])
			case "VALUE":
				out = append(out, h[1])
			default:
				out = append(out, h[0], h[1])
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported field to match")
}

func positional(pos, v, s string) (bool, error) {
	switch pos {
	case "CONTAINS":
		return strings.Contains(v, s), nil
	case "STARTS_WITH":
		return strings.HasPrefix(v, s), nil
	case "ENDS_WITH":
		return strings.HasSuffix(v, s), nil
	case "EXACTLY":
		return v == s, nil
	}
	return false, fmt.Errorf("unsupported positional constraint %q", pos)
}

func compare(op string, a, b int64) (bool, error) {
	switch op {
	case "EQ":
		return a == b, nil
	case "NE":
		return a != b, nil
	case "LE":
		return a <= b, nil
	case "LT":
		return a < b, nil
	case "GE":
		return a >= b, nil
	case "GT":
		return a > b, nil
	}
	return false, fmt.Errorf("unsupported comparison operator %q", op)
}

func transform(v string, tt []TextTransformation) (string, error) {
	for _, t := range tt {
		switch t.Type {
		case None:
		case URLDecode:
			v = urlDecode(v)
		case Lowercase:
			v = strings.ToLower(v)
		case CompressWhiteSpace:
			v = strings.Join(strings.FieldsFunc(v, unicode.IsSpace), " ")
		case HTMLEntityDecode:
			v = html.UnescapeString(v)
		case JSDecode:
			v = jsDecode(v)
		case NormalizePath:
			v = normalizePath(v)
		case NormalizePathWin:
			v = normalizePath(strings.ReplaceAll(v, `\`, "/"))
		default:
			return "", fmt.Errorf("unsupported text transformation %q", t.Type)
		}
	}
	return v, nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// urlDecode は %XX と + を戻す。正しくない %XX はそのまま残す。
func urlDecode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '%' && i+2 < len(s):
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
			b.WriteByte(c)
		case c == '+':
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// jsDecode は \uHHHH・\xHH・\n などの JavaScript のエスケープを戻す。
func jsDecode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch n := s[i+1]; n {
		case 'u':
			if i+5 < len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+6], 16, 32); err == nil {
					b.WriteRune(rune(v))
					i += 5
					continue
				}
			}
			b.WriteByte(s[i])
		case 'x':
			if i+3 < len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
					b.WriteByte(byte(v))
					i += 3
					continue
				}
			}
			b.WriteByte(s[i])
		case 'n':
			b.WriteByte('\n')
			i++
		case 'r':
			b.WriteByte('\r')
			i++
		case 't':
			b.WriteByte('\t')
			i++
		default:
			b.WriteByte(n)
			i++
		}
	}
	return b.String()
}

// normalizePath は連続するスラッシュ、/./、先頭以外の /../ を取り除く。
func normalizePath(p string) string {
	leading := strings.HasPrefix(p, "/")
	trailing := strings.HasSuffix(p, "/")
	var out []string
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "", ".":
		case "..":
			if len(out) > 0 && out[len(out)-1] != ".." {
				out = out[:len(out)-1]
			} else {
				out = append(out, "..")
			}
		default:
			out = append(out, seg)
		}
	}
	res := strings.Join(out, "/")
	if leading {
		res = "/" + res
	}
	if trailing && res != "/" {
		res += "/"
	}
	return res
}
