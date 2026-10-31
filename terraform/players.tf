# プレイヤーごとの「自分の設定しか触れない」仕組み。
#   - ゲーム画面: プレイヤーごとの秘密のトークン付き URL で開いた人だけが、そのプレイヤーとして遊べる
#   - AWS コンソール: プレイヤーごとの IAM ユーザーは、自分の Web ACL と、名前が <project>-<player>- で始まる
#     IP セット / 正規表現パターンセットだけを変更でき、ログも自分のロググループだけを見られる

resource "random_password" "player_token" {
  for_each = toset(local.players)

  length  = 32
  special = false
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  wafv2_arn  = "arn:aws:wafv2:${var.region}:${local.account_id}:regional"
}

resource "aws_iam_user" "player" {
  for_each = var.create_player_users ? toset(local.players) : toset([])

  name          = "${var.project}-${each.key}"
  force_destroy = true
}

resource "aws_iam_user_login_profile" "player" {
  for_each = aws_iam_user.player

  user                    = each.value.name
  password_length         = 20
  password_reset_required = false
}

data "aws_iam_policy_document" "player" {
  for_each = aws_iam_user.player

  # コンソールで一覧や画面を表示するための読み取り (他人のルールの中身は読めない)
  statement {
    sid = "ConsoleReadOnly"
    actions = [
      "wafv2:List*",
      "wafv2:Describe*",
      "wafv2:CheckCapacity",
      "wafv2:GetWebACLForResource",
      "cloudwatch:GetMetricData",
      "cloudwatch:GetMetricStatistics",
      "cloudwatch:ListMetrics",
      "elasticloadbalancing:Describe*",
      "logs:DescribeLogGroups",
      "logs:DescribeQueries",
      "logs:DescribeQueryDefinitions",
      "logs:GetQueryResults",
      "logs:StopQuery",
      "iam:GetAccountPasswordPolicy",
    ]
    resources = ["*"]
  }

  # 自分の Web ACL・IP セット・正規表現パターンセット・マネージドルールだけを読む
  statement {
    sid     = "ReadOwnResources"
    actions = ["wafv2:Get*"]
    resources = [
      aws_wafv2_web_acl.player[each.key].arn,
      "${local.wafv2_arn}/ipset/${var.project}-${each.key}-*/*",
      "${local.wafv2_arn}/regexpatternset/${var.project}-${each.key}-*/*",
      "arn:aws:wafv2:${var.region}:*:regional/managedruleset/*/*",
    ]
  }

  # 自分の Web ACL のルールだけを変更できる (使う IP セットなども自分のものに限る)
  statement {
    sid     = "UpdateOwnWebACL"
    actions = ["wafv2:UpdateWebACL"]
    resources = [
      aws_wafv2_web_acl.player[each.key].arn,
      "${local.wafv2_arn}/ipset/${var.project}-${each.key}-*/*",
      "${local.wafv2_arn}/regexpatternset/${var.project}-${each.key}-*/*",
      "arn:aws:wafv2:${var.region}:*:regional/managedruleset/*/*",
    ]
  }

  # 名前が <project>-<player>- で始まる IP セット / 正規表現パターンセットだけを作成・変更・削除できる
  statement {
    sid = "ManageOwnSets"
    actions = [
      "wafv2:CreateIPSet",
      "wafv2:UpdateIPSet",
      "wafv2:DeleteIPSet",
      "wafv2:CreateRegexPatternSet",
      "wafv2:UpdateRegexPatternSet",
      "wafv2:DeleteRegexPatternSet",
      "wafv2:TagResource",
      "wafv2:ListTagsForResource",
    ]
    resources = [
      "${local.wafv2_arn}/ipset/${var.project}-${each.key}-*/*",
      "${local.wafv2_arn}/regexpatternset/${var.project}-${each.key}-*/*",
    ]
  }

  # 自分の WAF ログだけを Logs Insights で調べられる
  statement {
    sid = "QueryOwnLogs"
    actions = [
      "logs:StartQuery",
      "logs:FilterLogEvents",
      "logs:GetLogEvents",
      "logs:DescribeLogStreams",
      "logs:GetLogGroupFields",
    ]
    resources = [
      aws_cloudwatch_log_group.waf[each.key].arn,
      "${aws_cloudwatch_log_group.waf[each.key].arn}:*",
    ]
  }

  statement {
    sid       = "ChangeOwnPassword"
    actions   = ["iam:ChangePassword"]
    resources = [each.value.arn]
  }

  # ゲームの仕組みそのもの (Web ACL の削除、ALB との関連付け、ログ設定) は誰も変えられない
  statement {
    sid    = "ProtectGameSetup"
    effect = "Deny"
    actions = [
      "wafv2:DeleteWebACL",
      "wafv2:AssociateWebACL",
      "wafv2:DisassociateWebACL",
      "wafv2:PutLoggingConfiguration",
      "wafv2:DeleteLoggingConfiguration",
      "wafv2:CreateWebACL",
    ]
    resources = ["*"]
  }
}

# インラインポリシーは 2,048 バイトまでなので、管理ポリシーとして作ってユーザーに付ける
resource "aws_iam_policy" "player" {
  for_each = aws_iam_user.player

  name   = "${var.project}-${each.key}"
  policy = data.aws_iam_policy_document.player[each.key].json
}

resource "aws_iam_user_policy_attachment" "player" {
  for_each = aws_iam_user.player

  user       = each.value.name
  policy_arn = aws_iam_policy.player[each.key].arn
}
