# WAF Dojo 管理者ガイド

WAF Dojo を用意して、参加者に遊んでもらうまでの手順と、開催中・開催後の運用をまとめたガイドです。社内研修などで使う場合の条件は、[ライセンス](../README.md#ライセンス) を確認してください。参加者に配る説明は [プレイヤー向けのはじめ方](PLAYER_GUIDE.md) にあります。

- [1. 全体像](#1-全体像)
- [2. 準備するもの](#2-準備するもの)
- [3. 環境を作る](#3-環境を作る)
- [4. 参加者に配る](#4-参加者に配る)
- [5. 開催中の運用](#5-開催中の運用)
- [6. 困ったとき](#6-困ったとき)
- [7. 片付け](#7-片付け)
- [8. セキュリティについて](#8-セキュリティについて)
- [9. 作られるもの](#9-作られるもの)

---

## 1. 全体像

```
参加者のブラウザ ──▶ ゲーム画面 (Lambda Function URL)
                         │ 攻撃開始
                         ▼
                    攻撃・採点用の Lambda ──HTTPS──▶ 参加者ごとの ALB ◀── 参加者ごとの Web ACL
                                                         │                  ▲
                                                         ▼                  │ ルールを設定
                                                   ダミーの EC サイト     参加者 (AWS コンソール)
```

- 参加者 1 人につき、**ALB と Web ACL が 1 つずつ**作られます。参加者は自分の Web ACL にルールを設定して、ゲーム画面から攻撃を開始します。
- 攻撃は、その参加者自身の ALB にだけ送られます。外部のサイトには送りません。
- 攻撃の結果 (ブロックできた攻撃・誤ってブロックした正常な通信) から自動で採点され、ランキングに反映されます。

参加者が触れるのは「ゲーム画面 (自分専用の URL)」と「AWS コンソール (自分専用の IAM ユーザー)」の 2 つだけです。どちらも、他の参加者の設定や記録は変更できません ([8. セキュリティについて](#8-セキュリティについて))。

---

## 2. 準備するもの

| もの | 内容 |
|---|---|
| AWS アカウント | 学習専用のアカウントをおすすめします。本番や他の用途のアカウントは避けてください |
| 権限 | 管理者に近い権限 (VPC・ALB・WAF・Lambda・DynamoDB・IAM・ACM・CloudWatch Logs を作成できること) |
| ツール | Go 1.26 以上、Terraform 1.6 以上、AWS CLI v2、make、Python 3 |
| 費用の目安 | 参加者 1 人あたり月 25〜45 ドル程度 (東京リージョンの ALB が約 18 ドル、Web ACL が 2 つで 10 ドル、ルール 1 つにつき 1 ドル、CloudFront は使った分だけ、など)。1 日あたりなら 1 人 1〜1.5 ドル程度です。Body の検査上限を 16 KB より大きくすると追加料金がかかります。開催期間だけ起動し、終わったら片付けるのがおすすめです |

> **必ず確認**: 作業を始める前に、AWS CLI がどのアカウントを向いているかを確認してください。手元の既定のプロファイルが別のアカウントになっていることがあります。
>
> ```sh
> aws sts get-caller-identity
> ```
>
> SSO の一時認証情報を使う場合は、ターミナルで `export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...` をしてから、上のコマンドでアカウント ID を確かめます。

---

## 3. 環境を作る

### 3-1. 設定ファイルを用意する (任意)

```sh
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
```

主な設定:

| 設定 | 意味 | 既定 |
|---|---|---|
| `player_count` | 参加人数。`player1`〜`playerN` が作られる | (設定しないと、実行時に聞かれる) |
| `players` | 参加者の名前を自分で決めたいとき (`["alice", "bob"]` など)。指定すると `player_count` より優先 | なし |
| `create_player_users` | 参加者ごとにコンソール用の IAM ユーザーを作るか。組織のルールで IAM ユーザーを作れないときは `false` | `true` |
| `enable_cloudfront` | 参加者ごとに CloudFront と CloudFront 用の Web ACL を作り、CloudFront の Body の検査上限を体験できるようにするか。`false` にすると CloudFront を使う問題 (ラボ Level 4 の 1 問) は遊べない | `true` |
| `game_passcode` | ゲーム画面全体にかけるパスコード | なし |
| `region` | リージョン | `ap-northeast-1` |

### 3-2. デプロイする

```sh
aws sts get-caller-identity   # アカウントを確認
make deploy
```

`make deploy` は、テスト → Lambda のビルド → `terraform apply` を順に行います。`terraform.tfvars` に `player_count` を書いていなければ、途中で参加人数を聞かれます。

```
var.player_count
  プレイ人数。player1, player2, ... のプレイヤーを作り、1 人につき ALB と Web ACL を 1 つずつ用意する。

  Enter a value: 3
```

作成内容が表示されたら `yes` を入力します。初回は 10〜20 分ほどかかります (CloudFront の作成に時間がかかります)。

### 3-3. 動作を確認する

```sh
make players
```

参加者ごとの「ゲーム画面の URL」「コンソールのログイン情報」が表示されれば完了です。自分でも `player1` のゲーム画面の URL を開き、ロビーと案内役のまもりんが表示されることを確かめておくと安心です。

---

## 4. 参加者に配る

### 4-1. 配る情報を表示する

```sh
make players
```

```
=== player1 ===
  ゲーム画面      : https://xxxx.lambda-url.ap-northeast-1.on.aws/?player=player1&token=...
  コンソール      : https://<アカウントID>.signin.aws.amazon.com/console
  IAM ユーザー名  : wafdy-player1
  パスワード      : ...
  WAF コンソール  : https://console.aws.amazon.com/wafv2/homev2/web-acls?region=ap-northeast-1
  Web ACL         : wafdy-player1
  IP セット等の名前の先頭: wafdy-player1-
```

### 4-2. 1 人ずつ、本人にだけ渡す

参加者には、自分の分だけを、本人にだけ (DM やパスワード付きのメモなどで) 渡してください。

- **ゲーム画面の URL**: 秘密のトークンが入っています。この URL を知っている人は、その参加者としてプレイできます。
- **IAM ユーザー名とパスワード**: AWS コンソールへのログイン用です。

あわせて [プレイヤー向けのはじめ方](PLAYER_GUIDE.md) を共有してください。

### 4-3. 参加者に伝えておくとよいこと

- ゲーム画面とコンソールは、**それぞれの URL から開く**こと
- AWS コンソールでは、リージョンを **アジアパシフィック (東京)** にすること。ただし CloudFront を使う問題では、CloudFront 用の Web ACL (`wafdy-<自分の名前>-cf`) を **Global (CloudFront)** で開くこと
- IP セット・正規表現パターンセットの名前は **`wafdy-<自分の名前>-` で始める**こと (それ以外の名前では作れません)
- ルールを保存してから反映されるまで **30〜60 秒** かかること

---

## 5. 開催中の運用

### 進み具合を見る

ゲーム画面のロビーにある **ランキング** で、全員の段位・チュートリアルのクリア数・こなした問題の数・合計点を見られます。トークンなしでゲーム画面を開くと「観戦モード」になり、ランキングと問題だけを見られます。管理者や見学者はこちらを使ってください。

### 参加者を増やす・減らす

`player_count` を変えて、もう一度デプロイします。

```sh
make deploy          # 新しい人数を入力する
```

- 増やすと、増えた分 (例: 2 → 3 なら `player3`) だけが追加されます。既存の参加者の設定と記録はそのままです。
- 減らすと、番号の大きい参加者から削除されます (例: 3 → 2 なら `player3`)。その参加者の Web ACL・ALB・IAM ユーザーも削除されます。

### 参加者のルールを最初の状態に戻す

```sh
make reset-rules PLAYER=player1
```

その参加者の Web ACL のルールをすべて削除します。実行前に、操作する AWS アカウントと内容が表示され、確認を求められます。参加者が作った IP セットなどは残ります。

### 参加者の記録 (スコア) を消す

```sh
make reset-scores PLAYER=player1
```

その参加者のベストスコアをすべて削除します (チュートリアルのクリア状況も消えるので、ゲームモードなどは再びロックされます)。

### ゲーム画面の URL (トークン) を作り直す

URL が他の人に漏れたときは、その参加者のトークンだけを作り直せます。

```sh
terraform -chdir=terraform apply -var player_count=<今の人数> -replace='random_password.player_token["player1"]'
make players   # 新しい URL を確認して、本人に渡し直す
```

古い URL は使えなくなります。参加者の記録はそのまま残ります。

### コンソールのパスワードを作り直す

```sh
terraform -chdir=terraform apply -var player_count=<今の人数> -replace='aws_iam_user_login_profile.player["player1"]'
make players
```

### ゲーム画面全体にパスコードをかける

`terraform/terraform.tfvars` に `game_passcode = "..."` を書いてデプロイし直すと、ゲーム画面を開くときにパスコードを聞かれるようになります。トークンと組み合わせて使えます。

---

## 6. 困ったとき

| 症状 | 原因と対処 |
|---|---|
| ルールを正しく設定したのに、最初の数件だけすり抜けた | ルールの反映 (30〜60 秒) が間に合っていません。結果画面とまもりんが「反映待ちかも」と知らせます。少し待って、もう一度攻撃開始してください |
| コンソールで Web ACL が見つからない | (1) ログインしたアカウントが違う、(2) リージョンが東京になっていない、(3) スコープが CloudFront になっている、のどれかです。新しい WAF コンソールでは、メニュー名が「Protection packs (web ACLs)」になっていることがあります |
| IP セットを作ろうとすると権限エラーになる | 名前が `wafdy-<自分の名前>-` で始まっていません |
| ルールを追加できない (容量のエラー) | Web ACL のルールの重さ (WCU) の上限 (既定 1,500) を超えています。こなした問題のルールを削除してもらってください。Level 4 で使う Core rule set だけで 700 WCU を使います |
| ゲーム画面で「自分専用の URL から開いてください」と出る | トークンなしで開いています。`make players` の URL から開き直してもらってください |
| 結果に「通信エラー」が多い | ALB がリクエストを拒否 (400) しています。通常は起きませんが、続く場合は CloudWatch Logs の `/aws/lambda/wafdy-trafficgen` を確認してください |
| 攻撃開始を押しても「別の攻撃が実行中」と出る | 同じ参加者の攻撃は 1 つずつしか実行できません。実行中の攻撃が終わる (最大 3〜5 分) まで待ってください |
| `terraform` が認証エラーになる | SSO の一時認証情報の有効期限が切れています。新しい認証情報を `export` し直してください |
| 他の参加者の設定を変えられてしまった | 参加者に SSO (管理者権限) を渡していないか確認してください。配った IAM ユーザーでは他の参加者の設定は変更できません |

### ログの場所

| ログ | 場所 (CloudWatch Logs) |
|---|---|
| 参加者ごとの WAF ログ | `aws-waf-logs-wafdy-<参加者名>` (CloudFront 用は us-east-1 の `aws-waf-logs-wafdy-<参加者名>-cf`) |
| 攻撃・採点 | `/aws/lambda/wafdy-trafficgen` |
| ゲーム画面の API | `/aws/lambda/wafdy-gameapi` |

---

## 7. 片付け

```sh
aws sts get-caller-identity   # アカウントを確認
make destroy
```

途中で参加人数を聞かれたら、今の人数を入力します。作成内容が表示されたら `yes` を入力します。CloudFront の削除には 10〜20 分ほどかかります。

- ALB・Web ACL・Lambda・DynamoDB・IAM ユーザー・ログなど、Terraform が作ったものはすべて削除されます。スコアの記録も消えます。
- **参加者がコンソールで作った IP セット・正規表現パターンセットは削除されません。** WAF コンソールの「IP sets」「Regex pattern sets」で、`wafdy-` で始まるものを削除してください。東京リージョンと Global (CloudFront) の両方を確認してください。
- 削除後、ALB と Web ACL が残っていないことを確認しておくと安心です。

```sh
aws elbv2 describe-load-balancers --query 'LoadBalancers[?starts_with(LoadBalancerName, `wafdy`)].LoadBalancerName'
aws wafv2 list-web-acls --scope REGIONAL --query 'WebACLs[?starts_with(Name, `wafdy`)].Name'
```

---

## 8. セキュリティについて

### 参加者ができること・できないこと

参加者用の IAM ユーザーの権限は、IAM ポリシーシミュレーターで確認済みです。

| できる | できない |
|---|---|
| 自分の Web ACL のルールの変更 | 他の参加者の Web ACL のルールを見る・変える |
| `wafdy-<自分>-` で始まる IP セット・正規表現パターンセットの作成・変更・削除 | 他の参加者の IP セットやログに触れる |
| 自分の WAF ログを Logs Insights で調べる | Web ACL の削除、ALB との関連付けの変更、ログ設定の変更 |
| マネージドルールの一覧や中身を見る | スコアの書き換え、攻撃用 Lambda の直接実行 |

ただし、参加者は他の参加者の **Web ACL の名前** と、WAF の **メトリクス** (ブロックした数など) は見られます (AWS の仕組み上、絞り込めないため)。ルールの中身は見えません。

### 管理者が気をつけること

- **参加者に SSO や管理者権限を渡さない**でください。管理者権限があれば、すべての設定を変更できます。
- **Terraform の状態ファイル** (`terraform/terraform.tfstate`) には、参加者のパスワードとトークンが含まれます。共有したり Git に含めたりしないでください (`.gitignore` で除外済み)。
- ゲーム画面の URL 自体は公開されています。トークンのない人は観戦しかできませんが、ランキングや問題を見せたくない場合は `game_passcode` を設定してください。
- 攻撃のリクエストは、実際の攻撃の「形」だけを再現した無害なもので、送り先はこの環境の ALB だけです。外部の宛先には `attacker.example` などの予約ドメインを使っています。

---

## 9. 作られるもの

| 種類 | 名前 | 個数 |
|---|---|---|
| VPC・サブネット | `wafdy` | 1 |
| ALB (HTTPS, 自己署名証明書) | `wafdy-<参加者>` | 参加者ごと |
| WAF Web ACL (ALB 用、東京リージョン) | `wafdy-<参加者>` | 参加者ごと |
| CloudFront | コメントが `wafdy-<参加者>` | 参加者ごと |
| WAF Web ACL (CloudFront 用、us-east-1) | `wafdy-<参加者>-cf` | 参加者ごと |
| CloudWatch Logs (CloudFront 用 WAF ログ、us-east-1) | `aws-waf-logs-wafdy-<参加者>-cf` | 参加者ごと |
| CloudWatch Logs (WAF ログ) | `aws-waf-logs-wafdy-<参加者>` | 参加者ごと |
| IAM ユーザー (コンソール用) | `wafdy-<参加者>` | 参加者ごと |
| Lambda | `wafdy-targetapp` (ダミーの EC サイト)、`wafdy-trafficgen` (攻撃・採点)、`wafdy-gameapi` (ゲーム画面) | 3 |
| DynamoDB | `wafdy` (実行結果・ベストスコア) | 1 |

### よく使うコマンド

| コマンド | 内容 |
|---|---|
| `make deploy` | テスト → ビルド → デプロイ |
| `make players` | 参加者に配る情報を表示 |
| `make reset-rules PLAYER=<名前>` | 参加者の Web ACL のルールを空にする |
| `make reset-scores PLAYER=<名前>` | 参加者の記録を消す |
| `make destroy` | すべて片付ける |
| `make dev` | AWS なしで画面だけをローカルで確認する (http://127.0.0.1:8080) |
| `make test` | テストを実行する |
