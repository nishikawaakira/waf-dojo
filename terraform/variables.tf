variable "region" {
  description = "デプロイ先のリージョン"
  type        = string
  default     = "ap-northeast-1"
}

variable "project" {
  description = "リソース名の接頭辞"
  type        = string
  default     = "wafdy"
}

variable "player_count" {
  description = "プレイ人数。player1, player2, ... のプレイヤーを作り、1 人につき ALB と Web ACL を 1 つずつ用意する。"
  type        = number

  validation {
    condition     = var.player_count >= 1 && var.player_count <= 20 && floor(var.player_count) == var.player_count
    error_message = "プレイ人数は 1〜20 の整数にしてください。"
  }
}

variable "players" {
  description = "プレイヤー名を自分で決めたいときだけ指定する (指定すると player_count より優先)。"
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for p in var.players : can(regex("^[a-z0-9][a-z0-9-]{0,19}$", p))])
    error_message = "プレイヤー名は英小文字・数字・ハイフンで 20 文字以内にしてください。"
  }
}

variable "create_player_users" {
  description = "プレイヤーごとに、自分の Web ACL しか触れない IAM ユーザー (コンソール用) を作るか。"
  type        = bool
  default     = true
}

locals {
  players = length(var.players) > 0 ? var.players : [for i in range(var.player_count) : "player${i + 1}"]
}

variable "enable_cloudfront" {
  description = "プレイヤーごとに CloudFront と CloudFront 用の Web ACL を作り、CloudFront の Body の検査上限を体験できるようにするか。"
  type        = bool
  default     = true
}

variable "game_passcode" {
  description = "ゲーム画面のパスコード。空ならパスコードなしで誰でも遊べる。"
  type        = string
  default     = ""
  sensitive   = true
}

variable "waf_log_retention_days" {
  description = "WAF ログの保存日数"
  type        = number
  default     = 7
}
