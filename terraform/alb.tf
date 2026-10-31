# プレイヤーごとの攻撃対象。ALB 1 つにつき Web ACL は 1 つしか関連付けられないため、
# 複数人で同時に遊べるようにプレイヤーごとに ALB を分ける。後ろの Lambda は共通。

# JA4 フィンガープリントは TLS の ClientHello から計算されるため、ALB は HTTPS で受ける。
# 学習用なのでドメインは使わず、自己署名証明書を ACM にインポートする。
# （トラフィック生成器は自分の ALB にしか送らないので、証明書の検証はしない）
resource "tls_private_key" "alb" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "alb" {
  private_key_pem       = tls_private_key.alb.private_key_pem
  validity_period_hours = 24 * 365
  allowed_uses          = ["key_encipherment", "digital_signature", "server_auth"]

  subject {
    common_name  = "shop.wafdojo.example"
    organization = "WAF Dojo"
  }

  dns_names = ["shop.wafdojo.example"]
}

resource "aws_acm_certificate" "alb" {
  private_key      = tls_private_key.alb.private_key_pem
  certificate_body = tls_self_signed_cert.alb.cert_pem

  lifecycle {
    create_before_destroy = true
  }
}

# トラフィック生成 Lambda は VPC の外から ALB の公開 DNS に送るため、443 番は全体に開ける。
resource "aws_security_group" "alb" {
  name        = "${var.project}-alb"
  description = "wafdojo target ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "target" {
  for_each = toset(local.players)

  name               = "${var.project}-${each.key}"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
}

resource "aws_lb_target_group" "target" {
  for_each = toset(local.players)

  name        = "${var.project}-${each.key}"
  target_type = "lambda"
}

resource "aws_lambda_permission" "alb" {
  for_each = toset(local.players)

  statement_id  = "AllowALB-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.targetapp.function_name
  principal     = "elasticloadbalancing.amazonaws.com"
  source_arn    = aws_lb_target_group.target[each.key].arn
}

resource "aws_lb_target_group_attachment" "target" {
  for_each = toset(local.players)

  target_group_arn = aws_lb_target_group.target[each.key].arn
  target_id        = aws_lambda_function.targetapp.arn

  depends_on = [aws_lambda_permission.alb]
}

resource "aws_lb_listener" "https" {
  for_each = toset(local.players)

  load_balancer_arn = aws_lb.target[each.key].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.alb.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.target[each.key].arn
  }
}
