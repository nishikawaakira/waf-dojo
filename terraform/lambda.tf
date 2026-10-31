# Lambda のバイナリは `make build` で ../build/<name>/bootstrap に作られる。
locals {
  functions = toset(["targetapp", "trafficgen", "gameapi"])
}

data "archive_file" "fn" {
  for_each = local.functions

  type        = "zip"
  source_file = "${path.module}/../build/${each.key}/bootstrap"
  output_path = "${path.module}/../build/${each.key}.zip"
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "fn" {
  for_each = local.functions

  name               = "${var.project}-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "logs" {
  for_each = local.functions

  role       = aws_iam_role.fn[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_cloudwatch_log_group" "fn" {
  for_each = local.functions

  name              = "/aws/lambda/${var.project}-${each.key}"
  retention_in_days = 14
}

# ---------- 攻撃対象のダミーアプリ ----------

resource "aws_lambda_function" "targetapp" {
  function_name    = "${var.project}-targetapp"
  role             = aws_iam_role.fn["targetapp"].arn
  runtime          = "provided.al2023"
  architectures    = ["arm64"]
  handler          = "bootstrap"
  filename         = data.archive_file.fn["targetapp"].output_path
  source_code_hash = data.archive_file.fn["targetapp"].output_base64sha256
  memory_size      = 128
  timeout          = 5

  depends_on = [aws_cloudwatch_log_group.fn]
}

# ---------- トラフィック生成・採点 ----------

data "aws_iam_policy_document" "trafficgen" {
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"]
    resources = [aws_dynamodb_table.game.arn]
  }
}

resource "aws_iam_role_policy" "trafficgen" {
  role   = aws_iam_role.fn["trafficgen"].id
  policy = data.aws_iam_policy_document.trafficgen.json
}

resource "aws_lambda_function" "trafficgen" {
  function_name    = "${var.project}-trafficgen"
  role             = aws_iam_role.fn["trafficgen"].arn
  runtime          = "provided.al2023"
  architectures    = ["arm64"]
  handler          = "bootstrap"
  filename         = data.archive_file.fn["trafficgen"].output_path
  source_code_hash = data.archive_file.fn["trafficgen"].output_base64sha256
  memory_size      = 256
  timeout          = 300

  environment {
    variables = {
      TABLE_NAME = aws_dynamodb_table.game.name
      # 送信先はここで決めた自分の ALB だけ
      TARGETS            = jsonencode({ for p in local.players : p => "https://${aws_lb.target[p].dns_name}" })
      TARGETS_CLOUDFRONT = jsonencode({ for p in local.cf_players : p => "https://${aws_cloudfront_distribution.player[p].domain_name}" })
    }
  }

  depends_on = [aws_cloudwatch_log_group.fn]
}

# 非同期呼び出しが失敗しても再実行しない（二重に攻撃・採点しないため）
resource "aws_lambda_function_event_invoke_config" "trafficgen" {
  function_name          = aws_lambda_function.trafficgen.function_name
  maximum_retry_attempts = 0
}

# ---------- ゲーム画面と API (Lambda Function URL) ----------

data "aws_iam_policy_document" "gameapi" {
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Scan"]
    resources = [aws_dynamodb_table.game.arn]
  }

  statement {
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.trafficgen.arn]
  }
}

resource "aws_iam_role_policy" "gameapi" {
  role   = aws_iam_role.fn["gameapi"].id
  policy = data.aws_iam_policy_document.gameapi.json
}

resource "aws_lambda_function" "gameapi" {
  function_name    = "${var.project}-gameapi"
  role             = aws_iam_role.fn["gameapi"].arn
  runtime          = "provided.al2023"
  architectures    = ["arm64"]
  handler          = "bootstrap"
  filename         = data.archive_file.fn["gameapi"].output_path
  source_code_hash = data.archive_file.fn["gameapi"].output_base64sha256
  memory_size      = 256
  timeout          = 15

  environment {
    variables = {
      TABLE_NAME          = aws_dynamodb_table.game.name
      TRAFFICGEN_FUNCTION = aws_lambda_function.trafficgen.function_name
      PLAYERS             = jsonencode(local.players)
      PROJECT             = var.project
      GAME_PASSCODE       = var.game_passcode
      CLOUDFRONT_ENABLED  = tostring(var.enable_cloudfront)
      # プレイヤーごとのトークンのハッシュ。自分の URL (トークン付き) で開いた人だけが、そのプレイヤーとして遊べる
      PLAYER_TOKEN_HASHES = jsonencode({ for p in local.players : p => sha256(random_password.player_token[p].result) })
    }
  }

  depends_on = [aws_cloudwatch_log_group.fn]
}

resource "aws_lambda_function_url" "gameapi" {
  function_name      = aws_lambda_function.gameapi.function_name
  authorization_type = "NONE"
}

# 認証なしの Function URL には、この 2 つの許可が両方必要
resource "aws_lambda_permission" "gameapi_url" {
  statement_id           = "AllowPublicFunctionUrl"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.gameapi.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "gameapi_invoke" {
  statement_id             = "AllowPublicInvokeViaFunctionUrl"
  action                   = "lambda:InvokeFunction"
  function_name            = aws_lambda_function.gameapi.function_name
  principal                = "*"
  invoked_via_function_url = true
}
