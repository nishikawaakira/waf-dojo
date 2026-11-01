output "game_url" {
  description = "ゲーム画面の URL (観戦用。プレイするには player_access の自分の URL を使う)"
  value       = aws_lambda_function_url.gameapi.function_url
}

output "players" {
  description = "プレイヤーごとの Web ACL と攻撃対象 ALB"
  value = {
    for p in local.players : p => {
      web_acl = aws_wafv2_web_acl.player[p].name
      alb_url = "https://${aws_lb.target[p].dns_name}"
      waf_log = aws_cloudwatch_log_group.waf[p].name
      cf_url  = try("https://${aws_cloudfront_distribution.player[p].domain_name}", null)
    }
  }
}

# 各プレイヤーに配る情報。terraform output -json player_access で表示する。
output "player_access" {
  description = "プレイヤーごとのゲーム URL (トークン付き) と、AWS コンソールのログイン情報"
  sensitive   = true
  value = {
    for p in local.players : p => {
      game_url       = "${aws_lambda_function_url.gameapi.function_url}?player=${p}&token=${random_password.player_token[p].result}"
      console_signin = "https://${data.aws_caller_identity.current.account_id}.signin.aws.amazon.com/console"
      console_user   = try(aws_iam_user.player[p].name, null)
      console_pass   = try(aws_iam_user_login_profile.player[p].password, null)
      waf_console    = "https://console.aws.amazon.com/wafv2/homev2/web-acls?region=${var.region}"
      web_acl        = aws_wafv2_web_acl.player[p].name
      cf_web_acl     = try(aws_wafv2_web_acl.player_cf[p].name, null)
      ipset_prefix   = "${var.project}-${p}-"
    }
  }
}

output "admin_url" {
  description = "管理者ページ (競技の開始・終了) の URL。管理者だけが持つこと"
  sensitive   = true
  value       = "${aws_lambda_function_url.gameapi.function_url}?admin=${random_password.admin_token.result}#/admin"
}
