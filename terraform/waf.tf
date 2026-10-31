# プレイヤーが自分でルールを足していく Web ACL。最初はルールなし（すべて許可）。
# ルールはコンソールで編集するので、Terraform は rule の差分を無視する。
resource "aws_wafv2_web_acl" "player" {
  for_each = toset(local.players)

  name        = "${var.project}-${each.key}"
  description = "WAF Dojo - ${each.key}"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project}-${each.key}"
    sampled_requests_enabled   = true
  }

  lifecycle {
    ignore_changes = [rule]
  }
}

resource "aws_wafv2_web_acl_association" "player" {
  for_each = toset(local.players)

  resource_arn = aws_lb.target[each.key].arn
  web_acl_arn  = aws_wafv2_web_acl.player[each.key].arn
}

# WAF ログ。ロググループ名は aws-waf-logs- で始める必要がある。
resource "aws_cloudwatch_log_group" "waf" {
  for_each = toset(local.players)

  name              = "aws-waf-logs-${var.project}-${each.key}"
  retention_in_days = var.waf_log_retention_days
}

data "aws_iam_policy_document" "waf_logs" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [for g in aws_cloudwatch_log_group.waf : "${g.arn}:*"]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "waf" {
  policy_name     = "${var.project}-waf-logs"
  policy_document = data.aws_iam_policy_document.waf_logs.json
}

resource "aws_wafv2_web_acl_logging_configuration" "player" {
  for_each = toset(local.players)

  resource_arn            = aws_wafv2_web_acl.player[each.key].arn
  log_destination_configs = [aws_cloudwatch_log_group.waf[each.key].arn]

  depends_on = [aws_cloudwatch_log_resource_policy.waf]
}
