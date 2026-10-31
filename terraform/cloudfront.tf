# CloudFront で Body の検査上限 (既定 16 KB、最大 64 KB) を体験するための環境。
#   攻撃・採点用の Lambda ─▶ プレイヤーの CloudFront ◀─ プレイヤーの CloudFront 用 Web ACL (us-east-1)
#                                   │
#                                   ▼
#                     ダミーの EC サイト (Lambda Function URL)
# CloudFront の後ろに ALB を置くと ALB 側の Web ACL も効いてしまうので、ダミーアプリを直接つなぐ。

locals {
  cf_players = var.enable_cloudfront ? toset(local.players) : toset([])
}

# ---------- CloudFront の転送先 (ダミーアプリの Function URL) ----------

resource "aws_lambda_function_url" "targetapp" {
  count = var.enable_cloudfront ? 1 : 0

  function_name      = aws_lambda_function.targetapp.function_name
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "targetapp_url" {
  count = var.enable_cloudfront ? 1 : 0

  statement_id           = "AllowPublicFunctionUrl"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.targetapp.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "targetapp_invoke" {
  count = var.enable_cloudfront ? 1 : 0

  statement_id             = "AllowPublicInvokeViaFunctionUrl"
  action                   = "lambda:InvokeFunction"
  function_name            = aws_lambda_function.targetapp.function_name
  principal                = "*"
  invoked_via_function_url = true
}

# ---------- プレイヤーごとの CloudFront 用 Web ACL ----------

resource "aws_wafv2_web_acl" "player_cf" {
  provider = aws.us_east_1
  for_each = local.cf_players

  name        = "${var.project}-${each.key}-cf"
  description = "WAF Dojo CloudFront - ${each.key}"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project}-${each.key}-cf"
    sampled_requests_enabled   = true
  }

  # ルールと Body の検査上限 (association_config) はプレイヤーがコンソールで変えるので、差分を無視する
  lifecycle {
    ignore_changes = [rule, association_config]
  }
}

resource "aws_cloudwatch_log_group" "waf_cf" {
  provider = aws.us_east_1
  for_each = local.cf_players

  name              = "aws-waf-logs-${var.project}-${each.key}-cf"
  retention_in_days = var.waf_log_retention_days
}

data "aws_iam_policy_document" "waf_cf_logs" {
  count = var.enable_cloudfront ? 1 : 0

  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [for g in aws_cloudwatch_log_group.waf_cf : "${g.arn}:*"]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:logs:us-east-1:${data.aws_caller_identity.current.account_id}:*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "waf_cf" {
  provider = aws.us_east_1
  count    = var.enable_cloudfront ? 1 : 0

  policy_name     = "${var.project}-waf-cf-logs"
  policy_document = data.aws_iam_policy_document.waf_cf_logs[0].json
}

resource "aws_wafv2_web_acl_logging_configuration" "player_cf" {
  provider = aws.us_east_1
  for_each = local.cf_players

  resource_arn            = aws_wafv2_web_acl.player_cf[each.key].arn
  log_destination_configs = [aws_cloudwatch_log_group.waf_cf[each.key].arn]

  depends_on = [aws_cloudwatch_log_resource_policy.waf_cf]
}

# ---------- プレイヤーごとの CloudFront ----------

data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}

# Function URL は Host ヘッダーが自分のドメインでないと受け付けないので、Host 以外のヘッダーを転送する
data "aws_cloudfront_origin_request_policy" "all_viewer_except_host" {
  name = "Managed-AllViewerExceptHostHeader"
}

resource "aws_cloudfront_distribution" "player" {
  for_each = local.cf_players

  enabled     = true
  comment     = "${var.project}-${each.key}"
  web_acl_id  = aws_wafv2_web_acl.player_cf[each.key].arn
  price_class = "PriceClass_200"

  origin {
    origin_id   = "targetapp"
    domain_name = trimsuffix(trimprefix(aws_lambda_function_url.targetapp[0].function_url, "https://"), "/")

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id         = "targetapp"
    viewer_protocol_policy   = "https-only"
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
