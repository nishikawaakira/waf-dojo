package scenario

import (
	"math/rand/v2"

	w "wafdy/internal/wafrule"
)

// 勧告の原文を読む問題。実際の勧告と同じように、必要な情報と関係のない情報が混ざっている。

var advisoryCondition = T("今回は防ぎ方の情報を整理していません。上の勧告から、ルールに必要な情報を自分で読み取ってください。",
	"This time nobody has summarized the mitigation for you. Read the advisory above and pick out the information your rule needs.")

func registerLabAdvisories() {
	lab(3, &Scenario{
		ID:    "lab-3-advisory-ivanti",
		CVE:   "CVE-2023-46805 / CVE-2024-21887",
		Title: T("勧告を読む: Ivanti Connect Secure の連鎖攻撃", "Reading an advisory: the Ivanti Connect Secure chain"),
		Summary: T("2 つの脆弱性を組み合わせた、認証なしのリモートコード実行。長い勧告から必要な情報を拾ってください。",
			"Two vulnerabilities chained into unauthenticated remote code execution. Pick the information you need out of a long advisory."),
		Topics: []Text{T("勧告を読む", "Reading advisories"), T("IoC からルールを作る", "Rules from IoCs")},
		Briefing: []Text{
			T("【概要】Ivanti Connect Secure および Ivanti Policy Secure の Web コンポーネントに、認証回避の脆弱性 (CVE-2023-46805) とコマンドインジェクションの脆弱性 (CVE-2024-21887) が存在します。2 つを組み合わせると、認証されていない攻撃者が任意のコマンドを実行できます。",
				"【Summary】The web components of Ivanti Connect Secure and Ivanti Policy Secure contain an authentication bypass (CVE-2023-46805) and a command injection (CVE-2024-21887). Chained together, they let an unauthenticated attacker run arbitrary commands."),
			T("【影響を受けるバージョン】9.x および 22.x のサポート対象のすべてのバージョン。",
				"【Affected versions】All supported versions of 9.x and 22.x."),
			T("【深刻度】CVE-2023-46805: CVSS 8.2 (High)、CVE-2024-21887: CVSS 9.1 (Critical)。",
				"【Severity】CVE-2023-46805: CVSS 8.2 (High); CVE-2024-21887: CVSS 9.1 (Critical)."),
			T("【悪用状況】限定的な標的型攻撃での悪用を確認しています。修正版の提供まで、緩和策の適用を強く推奨します。",
				"【Exploitation】Exploitation in limited targeted attacks has been observed. Applying the mitigation until fixed versions are available is strongly recommended."),
			T("【回避策】ダウンロードポータルから緩和用の XML ファイルをインポートしてください。なお、緩和策の適用中は一部の管理機能が使えなくなります。管理インターフェースをインターネットに公開しないことも推奨します。",
				"【Workaround】Import the mitigation XML file from the download portal. Some administrative functions are unavailable while the mitigation is applied. We also recommend not exposing the management interface to the internet."),
			T("【侵害の痕跡 (IoC)】研究者の分析によると、攻撃は 2 段階で行われます。まず、正規の API である /api/v1/totp/user-backup-code のあとに ../ を続けて、認証が必要な別の API に到達します (例: /api/v1/totp/user-backup-code/../../license/keys-status/)。次に、到達した API (例: .../system/maintenance/archiving/cloud-server-test-connection) の JSON パラメータにコマンドを埋め込みます。",
				"【Indicators of compromise】According to researcher analysis, the attack has two stages. First, it appends ../ to the legitimate API /api/v1/totp/user-backup-code to reach other APIs that require authentication (e.g. /api/v1/totp/user-backup-code/../../license/keys-status/). Then it embeds commands in JSON parameters of the reached API (e.g. .../system/maintenance/archiving/cloud-server-test-connection)."),
		},
		Conditions: []Text{
			advisoryCondition,
			T("/api/v1/totp/user-backup-code そのものは、2 要素認証のバックアップコードを使う正規の API です。",
				"/api/v1/totp/user-backup-code itself is a legitimate API used for two-factor backup codes."),
		},
		Hints: []Text{
			T("緩和用の XML や CVSS はルール作りには使いません。使えるのは IoC の段落です。",
				"The mitigation XML and the CVSS scores don't help build a rule. The IoC paragraph is what you can use."),
			T("2 段階目のコマンドの書き方は無数にあります。必ず通る 1 段階目 (user-backup-code のあとの ../) を止めましょう。../ はエンコードされることもあります。",
				"The second stage's commands can be written countless ways. Stop the first stage, which every attack must pass through (../ after user-backup-code). The ../ may be encoded."),
		},
		Patterns: []Pattern{
			{Attack, T("ライセンス情報の窃取 (IoC の例)", "Stealing license info (the IoC example)"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/api/v1/totp/user-backup-code/../../license/keys-status/;", ""))
			}},
			{Attack, T("コマンドインジェクション", "Command injection"), 10, func(r *rand.Rand) Request {
				return atk(r, postJSON(r, "/api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection",
					`{"type":";echo wafdy-test;","txtGCPProject":"a","txtGCPSecret":"a","txtGCPPath":"a","txtGCPBucket":"a"}`))
			}},
			{Attack, T("../ をエンコード", "Encoded ../"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/api/v1/totp/user-backup-code/%2e%2e/%2e%2e/license/keys-status/", ""))
			}},
			{Attack, T("スラッシュもエンコード", "Slashes encoded too"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/api/v1/totp/user-backup-code/..%2f..%2fsystem/active-users", ""))
			}},
			{Benign, T("2 要素認証と管理画面の正規の利用", "Legitimate 2FA and admin use"), 25, func(r *rand.Rand) Request {
				return get(r, pick(r, []string{"/api/v1/totp/user-backup-code", "/api/v1/configuration/users/user-roles", "/dana-na/auth/url_default/welcome.cgi"}), "")
			}},
			{Benign, lblBrowse, 20, browse},
		},
		Solution: w.Block("block-ivanti-auth-bypass", w.And(
			w.StartsWith("/api/v1/totp/user-backup-code", w.UriPath(), w.Lowercase),
			w.Contains("../", w.UriPath(), w.URLDecode),
		)),
		SolutionNote: []Text{
			T("勧告の大半 (バージョン、CVSS、緩和用 XML) はルール作りには使いません。WAF のルールに必要なのは「どこに」「どんな形で」攻撃が来るかで、それは IoC の段落にあります。",
				"Most of the advisory (versions, CVSS, mitigation XML) isn't used to build the rule. A WAF rule needs where and in what form the attack arrives, and that's in the IoC paragraph."),
			T("連鎖攻撃では、すべての攻撃が通る「入口」(ここでは認証回避) を止めるのが効果的です。2 段階目のコマンドインジェクションは書き方が無数にあります。",
				"For chained attacks, it's effective to stop the entry point every attack passes through (here, the authentication bypass). The second-stage command injection can be written countless ways."),
		},
		Pitfall: w.Block("pitfall-ivanti", w.Contains("/license/keys-status", w.UriPath())),
		PitfallNote: []Text{
			T("IoC に出てくる到達先の API を止めるルールです。到達先は何通りもあるので、ほかの API を狙う攻撃やエンコードした攻撃がすり抜けます。",
				"This rule blocks the destination API mentioned in the IoC. There are many possible destinations, so attacks on other APIs and encoded attacks slip through."),
		},
	})

	lab(3, &Scenario{
		ID:    "lab-3-advisory-gitlab",
		CVE:   "CVE-2023-7028",
		Title: T("勧告を読む: GitLab のパスワードリセット乗っ取り", "Reading an advisory: GitLab password reset takeover"),
		Summary: T("パスワードリセットのメールが、攻撃者のメールアドレスにも届いてしまう脆弱性。勧告から攻撃の形を読み取ってください。",
			"Password reset emails can also be delivered to the attacker's address. Work out the shape of the attack from the advisory."),
		Topics: []Text{T("勧告を読む", "Reading advisories"), T("配列パラメータ", "Array parameters")},
		Briefing: []Text{
			T("【概要】GitLab Community Edition および Enterprise Edition で、ユーザーアカウントのパスワードリセットのメールが、確認されていないメールアドレスにも送信される問題がありました。攻撃者は操作なしに (ゼロクリックで) アカウントを乗っ取ることができます。",
				"【Summary】In GitLab Community Edition and Enterprise Edition, password reset emails for user accounts could be delivered to unverified email addresses. Attackers can take over accounts with no user interaction (zero-click)."),
			T("【深刻度】CVSS 10.0 (Critical)。",
				"【Severity】CVSS 10.0 (Critical)."),
			T("【影響を受けるバージョン】16.1 から 16.7.1 までなど。2 要素認証を有効にしているアカウントは乗っ取られませんが、パスワードはリセットされます。",
				"【Affected versions】16.1 through 16.7.1, among others. Accounts with two-factor authentication can't be taken over, but their passwords can still be reset."),
			T("【原因】パスワードリセットのフォーム (POST /users/password) で、メールアドレスのパラメータに複数の値 (配列) を指定できました。被害者のメールアドレスと攻撃者のメールアドレスの 2 つを指定すると、リセット用のリンクが両方に送られます。",
				"【Cause】The password reset form (POST /users/password) accepted multiple values (an array) for the email parameter. Supplying both the victim's and the attacker's address sends the reset link to both."),
			T("【確認方法】ログの /users/password へのリクエストで、params の値が配列 (user[email][]) になっているものがないか確認してください。",
				"【How to check】In your logs, look for requests to /users/password whose params value is an array (user[email][])."),
		},
		Conditions: []Text{
			advisoryCondition,
			T("正規のフォームは user[email] に 1 つのメールアドレスだけを送ります。API クライアントは同じ内容を JSON で送ることもあります。",
				"The legitimate form sends a single address in user[email]. API clients sometimes send the same thing as JSON."),
		},
		Hints: []Text{
			T("フォームでは user[email][] の [ ] が %5B%5D とエンコードされて届きます。小文字の %5b%5d のこともあります。",
				"In form posts, the [ ] in user[email][] arrive encoded as %5B%5D, sometimes in lowercase as %5b%5d."),
			T("JSON では \"email\": [ ... ] のように、値が [ で始まる配列になります。",
				"In JSON, the value becomes an array starting with [, as in \"email\": [ ... ]."),
		},
		Patterns: []Pattern{
			{Attack, T("フォームで 2 つのメールアドレス", "Two addresses in the form"), 10, func(r *rand.Rand) Request {
				return atk(r, post(r, "/users/password", "user%5Bemail%5D%5B%5D=victim%40example.com&user%5Bemail%5D%5B%5D=thief%40attacker.example"))
			}},
			{Attack, T("小文字でエンコード", "Lowercase encoding"), 10, func(r *rand.Rand) Request {
				return atk(r, post(r, "/users/password", "user%5bemail%5d%5b%5d=thief%40attacker.example&user%5bemail%5d%5b%5d=victim%40example.com"))
			}},
			{Attack, T("JSON の配列", "A JSON array"), 10, func(r *rand.Rand) Request {
				return atk(r, postJSON(r, "/users/password", `{"user":{"email":["victim@example.com","thief@attacker.example"]}}`))
			}},
			{Attack, T("空白を入れた JSON", "JSON with spaces"), 10, func(r *rand.Rand) Request {
				return atk(r, postJSON(r, "/users/password", `{"user": {"email" : [ "victim@example.com", "thief@attacker.example" ]}}`))
			}},
			{Benign, T("正規のパスワードリセット", "Legitimate password resets"), 25, func(r *rand.Rand) Request {
				switch r.IntN(3) {
				case 0:
					return post(r, "/users/password", "user%5Bemail%5D=me%40example.com")
				case 1:
					return postJSON(r, "/users/password", `{"user":{"email":"me@example.com"}}`)
				}
				return get(r, "/users/password/edit", "reset_password_token=wafdy"+randomText(r, 12))
			}},
			{Benign, lblBrowse, 20, browse},
		},
		Solution: w.Block("block-gitlab-reset-array", w.And(
			w.StartsWith("/users/password", w.UriPath(), w.Lowercase),
			w.Or(
				w.Contains("user[email][]", w.BodyField(), w.URLDecode, w.Lowercase),
				w.Regex(`"email"\s*:\s*\[`, w.BodyField()),
			),
		)),
		SolutionNote: []Text{
			T("勧告の「原因」の段落から「メールアドレスのパラメータが配列になる」という攻撃の本質を読み取り、フォームと JSON の 2 つの書き方に対応します。",
				"From the advisory's Cause paragraph, extract the essence — the email parameter becomes an array — and handle both form and JSON encodings."),
			T("URL decode をかけると %5B%5D と %5b%5d のどちらも [] になります。JSON は \"email\" のあとに [ が来るかを正規表現で調べます。",
				"URL decode turns both %5B%5D and %5b%5d into []. For JSON, a regex checks whether [ follows \"email\"."),
		},
		Pitfall: w.Block("pitfall-gitlab", w.Contains("user%5Bemail%5D%5B%5D", w.BodyField())),
		PitfallNote: []Text{
			T("エンコードされたままの文字列を探すルールです。小文字でエンコードした攻撃と、JSON の攻撃がすり抜けます。",
				"This rule searches for the still-encoded string. Lowercase-encoded attacks and JSON attacks slip through."),
		},
	})
}
