package scenario

import (
	"math/rand/v2"

	w "wafdy/internal/wafrule"
)

// registerLabHeaderFold は、ヘッダーの行折り返し (obs-fold) で Values スコープの検査を
// すり抜ける問題。CloudFront に届くと折り返した継続行がヘッダーの「キー」位置に入るため、
// Match scope = Values では見えず、All (キー+値) で初めて捕まえられる。実機で確認済み。
func registerLabHeaderFold() {
	const marker = "T(java.lang"
	exploit := "T(java.lang.Runtime).getRuntime().exec('id')"

	lab(4, &Scenario{
		ID:     "lab-4-header-fold",
		CVE:    "Header folding (obs-fold)",
		Target: TargetCloudFront,
		Title:  T("ヘッダーの行折り返しで検査をすり抜ける", "Slipping past header inspection with line folding"),
		Summary: T("すべてのヘッダーを検査しているのに、ヘッダーに仕込まれた式インジェクションがすり抜けました。攻撃は行折り返し (obs-fold) で送られていました。",
			"You inspect every header, yet an expression-injection payload in a header slipped through. It was sent using line folding (obs-fold)."),
		Topics: []Text{T("すべてのヘッダーの検査 (Match scope = All)", "Inspecting all headers (Match scope = All)"), T("ヘッダーの行折り返し (obs-fold)", "Header line folding (obs-fold)"), T("CloudFront の Web ACL", "CloudFront web ACLs")},
		Briefing: []Text{
			T("あるライブラリが一部のリクエストヘッダーを式として評価してしまう脆弱性が出ました。攻撃ペイロードには T(java.lang.Runtime) のような式が含まれます。勧告は「ヘッダーに T(java.lang を含むリクエストをブロックせよ」でした。",
				"A library has a flaw where it evaluates certain request headers as expressions. Attack payloads contain expressions like T(java.lang.Runtime). The advisory: block any request whose headers contain T(java.lang."),
			T("この問題の攻撃は、ALB ではなくあなた専用の CloudFront に届きます。設定するのは CloudFront に付いた Web ACL ({acl}) です (WAF コンソールのリージョンで「Global (CloudFront)」を選びます)。",
				"For this problem, attacks arrive at your own CloudFront distribution, not the ALB. Configure the web ACL attached to CloudFront ({acl}) (choose \"Global (CloudFront)\" as the region in the WAF console)."),
			T("あなたは Shellshock のときと同じく「すべてのヘッダー (Headers)」を Match scope = Values で検査しました。ところが攻撃がすり抜けました。攻撃ヘッダーは途中で行折り返しされ、次の行がタブで継続されていました。",
				"As with Shellshock, you inspected \"Headers\" (all headers) with Match scope = Values. Yet the attack got through. The attack header was line-folded, with the next line continued by a tab."),
		},
		Conditions: []Text{
			T("正規のリクエストのヘッダーに T(java.lang が含まれることはありません。",
				"No legitimate request has T(java.lang in its headers."),
			T("攻撃は、ヘッダーを「名前: 値 <改行> <タブ>ペイロード」と折り返して送ります。CloudFront に届くと、折り返した継続行はヘッダーの「キー (名前)」の位置に入ります。",
				"The attack folds a header as \"Name: value <newline> <tab>payload\". Reaching CloudFront, the folded continuation lands in the header's key (name) position."),
		},
		Lesson: []Text{
			T("【行折り返し (obs-fold)】HTTP/1.1 には、ヘッダーの値を次の行に (先頭を空白かタブにして) 続けて書く古い記法があります。今はほぼ使われず多くのサーバーは拒否しますが、CloudFront は受け取って継続行をオリジン側に渡します。",
				"【Line folding (obs-fold)】HTTP/1.1 has an old notation that continues a header value on the next line (starting with a space or tab). It is rarely used today and many servers reject it, but CloudFront accepts it and carries the continuation toward the origin."),
			T("【なぜ Values ですり抜けるか】CloudFront は折り返した継続行をヘッダーの「キー (名前)」として扱います (実機で確認)。Match scope = Values は値しか見ないので、キー位置に入ったペイロードを検査できません。Single header も、元のヘッダーの値には継続行が含まれないため外れます。",
				"【Why Values is bypassed】CloudFront treats the folded continuation as a header key/name (verified on real AWS). Match scope = Values inspects only values, so it can't see a payload that landed in the key position. A single-header rule also misses it, because the original header's value no longer contains the continuation."),
			T("【対処】Match scope を All (キーと値の両方) にすると、キー位置に入ったペイロードも検査できます。Key だけでも拾えますが、通常は All にして名前と値の両方を見ます。",
				"【Fix】Set Match scope to All (both keys and values) so a payload in the key position is inspected too. Key alone would also catch it, but All is the usual choice, inspecting both names and values."),
			T("【設計の考え方】こうした異常なリクエストの正規化は前段の CloudFront が担います。折り返しの有無で検査結果が変わらないよう、ヘッダー検査は値だけでなくキーも含めて見るのが安全です。",
				"【Design thinking】Normalizing odd requests like this is handled by CloudFront in front. So that folding doesn't change the outcome, it is safer to inspect header keys as well as values."),
		},
		Hints: []Text{
			T("Match scope = Values のままだと、折り返しでキー位置に移ったペイロードは見えません。",
				"With Match scope = Values, a payload moved to the key position by folding is invisible."),
			T("Match scope を All にして、ヘッダーのキーと値の両方を検査しましょう。",
				"Set Match scope to All so both header keys and values are inspected."),
		},
		Patterns: []Pattern{
			{Attack, T("X-Forwarded-Host に折り返して隠した式", "Expression folded into X-Forwarded-Host"), 10, func(r *rand.Rand) Request {
				return withFold(atk(r, get(r, "/account", "")), "X-Forwarded-Host", "shop.example", exploit)
			}},
			{Attack, T("独自ヘッダーに折り返して隠した式", "Expression folded into a custom header"), 10, func(r *rand.Rand) Request {
				return withFold(atk(r, get(r, "/account", "")), "X-Trace", "req-8f21", exploit)
			}},
			{Attack, T("折り返さず値に入れた式", "Expression placed plainly in a value"), 10, func(r *rand.Rand) Request {
				return withHeader(atk(r, get(r, "/account", "")), "X-Trace", exploit)
			}},
			{Benign, T("括弧やドットを含む正規のヘッダー", "Legitimate headers with parentheses and dots"), 15, func(r *rand.Rand) Request {
				req := withHeader(get(r, "/account", ""), "Referer", "https://www.example.com/sale(2026)/spring")
				return withHeader(req, "User-Agent", "Mozilla/5.0 (Macintosh) Java/11.0")
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("block-expr-all-headers", w.Contains(marker, w.AllHeaders())),
		SolutionNote: []Text{
			T("検査対象を Headers、Match scope を All (キーと値) にして、T(java.lang を Contains で探します。折り返しでキー位置に入ったペイロードも、素直に値に入ったペイロードも、どちらも捕まえられます。",
				"Inspect Headers with Match scope = All (keys and values) and look for T(java.lang with Contains. This catches both a payload moved to the key position by folding and one placed plainly in a value."),
			T("Match scope を Values にすると、折り返した攻撃を取りこぼします。Shellshock では Values で足りましたが、折り返しはキー位置に入るため All が必要です。",
				"With Match scope = Values you miss the folded attacks. Values was enough for Shellshock, but folding lands in the key position, so All is required here."),
		},
		Pitfall: w.Block("pitfall-values-only", w.Contains(marker, w.AllHeaderValues())),
		PitfallNote: []Text{
			T("Shellshock と同じく Headers を Match scope = Values で検査した状態です。素直に値に入った攻撃は止まりますが、行折り返しでキー位置に移った攻撃はすり抜けます。",
				"This inspects Headers with Match scope = Values, as in Shellshock. Attacks placed plainly in a value are stopped, but those moved to the key position by folding slip through."),
		},
	})
}
