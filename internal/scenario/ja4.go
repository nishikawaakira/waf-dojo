package scenario

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"

	"wafdy/internal/tlsprofile"
)

// JA4 を使うシナリオ。JA4 の値は実際に送る ClientHello から計算したものを画面に出す。

func ja4Parts(v string) (a, b, c string) {
	parts := strings.SplitN(v, "_", 3)
	return parts[0], parts[1], parts[2]
}

func withTLS(req Request, name tlsprofile.Name) Request {
	req.TLS = name
	return req
}

func registerJA4Tutorial() {
	tool := tlsprofile.JA4(tlsprofile.Scraper)
	chrome := tlsprofile.JA4(tlsprofile.Chrome)
	a, b, c := ja4Parts(tool)

	register(&Scenario{
		ID:       "tutorial-6-ja4",
		Title:    T("チュートリアル 6: JA4 フィンガープリントでツールを見抜く", "Tutorial 6: Unmask tools with JA4 fingerprints"),
		Tutorial: true,
		Summary: T(
			"ブラウザになりすましたスクレイピングツールが来ます。User-Agent や IP では見分けられないので、TLS の指紋 (JA4) で止めます。",
			"A scraping tool is impersonating a browser. You can't tell it apart by User-Agent or IP, so stop it by its TLS fingerprint (JA4).",
		),
		Topics:  []Text{T("JA4 フィンガープリント", "JA4 fingerprints"), T("TLS ClientHello", "TLS ClientHello"), T("WAF ログの分析", "Analyzing WAF logs")},
		ShowJA4: true,
		Briefing: []Text{
			T("商品ページを読み取るスクレイピングツールが動いています。User-Agent は Chrome そっくりに偽装されていて、送信元 IP も毎回変わります。チュートリアル 4 の文字列マッチも、チュートリアル 5 のレート制限も効きません。",
				"A scraping tool is reading product pages. Its User-Agent is a convincing copy of Chrome, and its source IP changes every time. Neither the string match from Tutorial 4 nor the rate limit from Tutorial 5 will catch it."),
			T("ただし、ツールが HTTPS で接続するときの「あいさつ」(TLS の ClientHello) は本物の Chrome とは違います。この違いを JA4 フィンガープリントで見分けます。",
				"However, the \"greeting\" the tool sends when it opens an HTTPS connection (the TLS ClientHello) differs from real Chrome. You'll tell them apart using the JA4 fingerprint."),
			T("このツールの JA4 は "+tool+" です。本物の Chrome は "+chrome+" のような値になります。",
				"This tool's JA4 is "+tool+". Real Chrome looks something like "+chrome+"."),
			clearNote,
		},
		Lesson: []Text{
			T("【JA4 とは】HTTPS の通信を始めるとき、クライアントは最初に ClientHello というメッセージで「使える TLS のバージョン」「暗号スイート」「拡張機能」などをサーバーに伝えます。この内容はブラウザやライブラリごとに決まっていて、User-Agent のように簡単には書き換えられません。JA4 は、ClientHello の内容を短い文字列にまとめた「指紋」です。",
				"【What is JA4?】When an HTTPS connection starts, the client first sends a ClientHello message telling the server which TLS versions, cipher suites, and extensions it supports. These are fixed by each browser or library and can't be changed as easily as a User-Agent. JA4 is a \"fingerprint\" that condenses the ClientHello into a short string."),
			T("【JA4 の読み方】JA4 は a_b_c の 3 つの部分でできています。このツールの JA4 "+tool+" を例にすると:",
				"【Reading a JA4】A JA4 has three parts: a_b_c. Taking this tool's JA4, "+tool+", as an example:"),
			T("a = "+a+" … t は TCP、"+a[1:3]+" は最大の TLS バージョン (1.3)、"+a[3:4]+" は SNI (接続先のホスト名) あり、続く 2 桁ずつが暗号スイートの数 ("+a[4:6]+") と拡張の数 ("+a[6:8]+")、最後の "+a[8:]+" は ALPN (HTTP/1.1) の先頭と末尾の文字です。人が読んで意味がわかる部分です。",
				"a = "+a+" … t means TCP, "+a[1:3]+" is the highest TLS version (1.3), "+a[3:4]+" means SNI (the destination host name) is present, the next two pairs of digits are the number of cipher suites ("+a[4:6]+") and extensions ("+a[6:8]+"), and the final "+a[8:]+" is the first and last character of the ALPN value (HTTP/1.1). This part is human-readable."),
			T("b = "+b+" … 暗号スイートの一覧を並べ替えてハッシュしたものです。同じライブラリなら同じ値になりやすい部分です。",
				"b = "+b+" … a hash of the sorted list of cipher suites. Clients built on the same library tend to share this value."),
			T("c = "+c+" … 拡張機能の一覧と署名アルゴリズムをハッシュしたものです。",
				"c = "+c+" … a hash of the list of extensions plus the signature algorithms."),
			T("並べ替えてからハッシュするので、Chrome のように拡張の順番を毎回シャッフルするクライアントでも JA4 は変わりません。前身の JA3 は順番の影響を受けていましたが、JA4 ではそれが改善されています。",
				"Because the lists are sorted before hashing, the JA4 stays the same even for clients like Chrome that shuffle their extension order on every connection. Its predecessor JA3 was sensitive to that order; JA4 fixes this."),
			T("【AWS WAF での使い方】ルールの検査対象に「JA4 fingerprint」を選ぶと、JA4 で条件を書けます。JA4 は HTTPS でしか計算されないので、取得できなかった場合の扱い (Fallback) も指定します。どの JA4 が来ているかは WAF ログの ja4Fingerprint フィールドで確認できます。",
				"【Using it in AWS WAF】Choose \"JA4 fingerprint\" as the field to inspect, and you can write conditions on JA4. Since JA4 is only computed for HTTPS, you also specify what happens when it's unavailable (Fallback). You can see which JA4 values are arriving in the ja4Fingerprint field of the WAF logs."),
		},
		Steps: []Text{
			T("（任意）先に、どんな JA4 が来ているかログで確かめましょう。CloudWatch の「Logs Insights」でロググループ aws-waf-logs-{acl} を選び、次のクエリを実行します: fields ja4Fingerprint | stats count(*) as requests by ja4Fingerprint | sort requests desc （まだログがない場合は、一度「攻撃開始」を押してから見ると、ツールの JA4 が上位に出てきます）",
				"(Optional) First, check which JA4 values are arriving. In CloudWatch \"Logs Insights\", select the log group aws-waf-logs-{acl} and run: fields ja4Fingerprint | stats count(*) as requests by ja4Fingerprint | sort requests desc (If there are no logs yet, press \"Start attack\" once and look again — the tool's JA4 will be near the top.)"),
			addOwnRule,
			T("「Rule builder」で Name に block-scraper-ja4 と入力し、「If a request」は「matches the statement」を選びます。",
				"In \"Rule builder\", enter block-scraper-ja4 as the Name and set \"If a request\" to \"matches the statement\"."),
			T("「Inspect」で「JA4 fingerprint」を選びます。", "Set \"Inspect\" to \"JA4 fingerprint\"."),
			T("「Match type」で「Exactly matches string」を選び、String to match に "+tool+" を入力します。",
				"Set \"Match type\" to \"Exactly matches string\" and enter "+tool+" as the String to match."),
			T("「Fallback for missing JA4 fingerprint」は「No match」を選びます。Text transformation は不要です（None）。",
				"Set \"Fallback for missing JA4 fingerprint\" to \"No match\". No text transformation is needed (None)."),
			blockAndSave,
			waitAndStart,
		},
		Duration: 30 * time.Second,
		Patterns: []Pattern{
			{Attack, T("Chrome を名乗るスクレイピングツール", "Scraping tool posing as Chrome"), 40, func(r *rand.Rand) Request {
				req := fromAttacker(get(r, "/products/"+strconv.Itoa(100+r.IntN(900)), ""), r)
				req.Headers["User-Agent"] = browserUAs[0]
				return withTLS(req, tlsprofile.Scraper)
			}},
			{Benign, T("一般ユーザーの閲覧 (本物のブラウザ)", "Regular users browsing (real browsers)"), 60, browse},
		},
	})
}

func registerJA4Game() {
	partner := tlsprofile.JA4(tlsprofile.HTTPLib)
	briefing := []Text{
		T("漏洩したメールアドレスとパスワードの組み合わせで POST /login を試すリスト型攻撃が始まりました。User-Agent は本物のブラウザと同じ、送信元 IP はすべて別々で、1 つの IP からは数回しか来ません。",
			"A credential-stuffing attack has begun, trying leaked email/password pairs against POST /login. The User-Agents match real browsers, every source IP is different, and each IP only sends a few requests."),
		T("ボットは JA4 を完全一致のルールで止められないよう、TLS の拡張機能やバージョンを少しずつ変えた亜種を使っています。これまでに観測された JA4 は次の 3 つですが、まだ観測されていない亜種もいるはずです。",
			"To avoid exact-match JA4 rules, the bots use variants that tweak their TLS extensions and versions. These three JA4 values have been observed so far, but there are surely variants nobody has seen yet."),
	}
	for _, n := range []tlsprofile.Name{tlsprofile.BotV1, tlsprofile.BotV2, tlsprofile.BotV3} {
		briefing = append(briefing, T("・"+tlsprofile.JA4(n), "• "+tlsprofile.JA4(n)))
	}
	briefing = append(briefing, T(
		"ボットは市販の HTTP ライブラリを改造して作られているようです。そして、取引先の在庫連携システム (GET /api/inventory) も同じライブラリを改造せずに使っています。取引先の JA4 は "+partner+" で、クラウド上で動いているため IP アドレスは決まっていません。取引先の通信は止めないでください。",
		"The bots appear to be built on a modified off-the-shelf HTTP library. A business partner's inventory sync system (GET /api/inventory) uses the same library, unmodified. The partner's JA4 is "+partner+", and because it runs in the cloud its IP address isn't fixed. Don't block the partner.",
	))

	bots := []struct {
		name  tlsprofile.Name
		label Text
	}{
		{tlsprofile.BotV1, T("ボット (亜種 1)", "Bot (variant 1)")},
		{tlsprofile.BotV2, T("ボット (亜種 2)", "Bot (variant 2)")},
		{tlsprofile.BotV3, T("ボット (亜種 3: SNI なし)", "Bot (variant 3: no SNI)")},
		{tlsprofile.BotV4, T("ボット (亜種 4: TLS 1.2 のみ・未観測)", "Bot (variant 4: TLS 1.2 only, unseen)")},
		{tlsprofile.BotV5, T("ボット (亜種 5: 拡張を追加・未観測)", "Bot (variant 5: extra extensions, unseen)")},
	}
	var patterns []Pattern
	for _, bot := range bots {
		patterns = append(patterns, Pattern{Attack, bot.label, 10, func(r *rand.Rand) Request {
			req := fromAttacker(post(r, "/login", form("username", fmt.Sprintf("victim%03d@example.com", r.IntN(1000)), "password", fmt.Sprintf("Summer%04d!", r.IntN(10000)))), r)
			return withTLS(req, bot.name)
		}})
	}
	patterns = append(patterns,
		Pattern{Benign, T("取引先の在庫連携システム", "Partner's inventory sync system"), 20, func(r *rand.Rand) Request {
			req := get(r, "/api/inventory", q("sku", fmt.Sprintf("SKU-%05d", r.IntN(100000))))
			req.Headers["User-Agent"] = "inventory-sync/2.4"
			req.ClientIP = fmt.Sprintf("198.51.100.%d", 200+r.IntN(50))
			return withTLS(req, tlsprofile.HTTPLib)
		}},
		Pattern{Benign, T("一般ユーザーのログイン", "Regular users logging in"), 20, func(r *rand.Rand) Request {
			return post(r, "/login", form("username", fmt.Sprintf("user%03d@example.com", r.IntN(1000)), "password", "correct-horse-battery"))
		}},
		Pattern{Benign, lblBrowse, 40, browse},
	)

	register(&Scenario{
		ID:    "game-6-ja4regex",
		Title: T("ステージ 6: 姿を変えるボット軍団", "Stage 6: The shape-shifting bot army"),
		Summary: T(
			"リスト型攻撃のボットが JA4 を少しずつ変えてきます。JA4 の共通部分を正規表現でとらえ、同じライブラリを使う取引先は通してください。",
			"Credential-stuffing bots keep shifting their JA4. Capture the shared part of the JA4 with a regex, and let through the partner that uses the same library.",
		),
		Topics:   []Text{T("JA4 の正規表現", "Regex on JA4"), T("正規表現パターンセット", "Regex pattern sets"), T("例外 (AND NOT)", "Exceptions (AND NOT)")},
		ShowJA4:  true,
		Briefing: briefing,
		Hints: []Text{
			T("観測された 3 つの JA4 を a_b_c に分けて見比べましょう。毎回変わる部分と、変わらない部分があります。",
				"Split the three observed JA4 values into a_b_c and compare them. Some parts change, and some don't."),
			T("「Inspect: JA4 fingerprint」と「Match type: Matches regular expression」(または正規表現パターンセット) を使うと、JA4 の一部だけで判定できます。例えば _xxxxxxxxxxxx_ のように b 部分を挟むと、a や c が変わっても一致します。",
				"With \"Inspect: JA4 fingerprint\" and \"Match type: Matches regular expression\" (or a regex pattern set), you can match on just part of the JA4. For example, wrapping the b part as _xxxxxxxxxxxx_ matches even when a or c changes."),
			T("a 部分を正規表現に含めるなら、TLS バージョン (12/13) や SNI の有無 (d/i) が変わる亜種がいることに注意しましょう。",
				"If you include the a part in your regex, remember that some variants change the TLS version (12/13) or SNI presence (d/i)."),
			T("取引先は b 部分もボットと同じです。「JA4 が正規表現に一致する」AND NOT「JA4 が取引先の値と完全一致」でブロックします。",
				"The partner shares the b part with the bots. Block when \"JA4 matches the regex\" AND NOT \"JA4 exactly matches the partner's value\"."),
		},
		PrepSeconds: 480,
		Duration:    30 * time.Second,
		Patterns:    patterns,
	})
}
