# Security Policy / セキュリティポリシー

## Scope / 対象

WAF Dojo is a **training environment**. It intentionally contains request shapes
and payload *markers* that look like attacks (XSS/SQLi/expression-injection
strings, odd HTTP framing, etc.). These exist to teach WAF rule writing and are
**not** vulnerabilities in this project.

WAF Dojo は学習用環境です。攻撃に見えるリクエスト形状やペイロードの「目印」
（XSS/SQLi/式インジェクションの文字列、変則的な HTTP フレーミング等）を
意図的に含みます。これらは WAF ルール作成を学ぶためのもので、本プロジェクトの
脆弱性ではありません。

A security issue here means something like: the game API leaking another
player's data, authentication/authorization bypass in the game or admin/contest
flow, or the deployment templates creating resources that are open to the
public by default.

## Reporting / 報告

Please **do not** open a public issue for a suspected vulnerability.

- Use GitHub's private vulnerability reporting: the **"Report a vulnerability"**
  button under this repository's **Security** tab.
- Or email: info@i-wind.jp

We aim to acknowledge reports within a few business days.
公開 Issue ではなく、上記の非公開経路でご連絡ください。数営業日以内に一次応答します。
