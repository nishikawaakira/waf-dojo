#!/usr/bin/env bash
# プレイヤーの Web ACL のルールを空に戻す (rules)、またはスコアの記録を消す (scores)。
#   使い方: tools/reset_player.sh rules  player1
#           tools/reset_player.sh scores player1
# 実行前に、操作する AWS アカウントを表示して確認を求める。
set -euo pipefail

what="${1:-}"; player="${2:-}"
project="${PROJECT:-wafdojo}"; region="${REGION:-ap-northeast-1}"
if [[ ! "$what" =~ ^(rules|scores)$ || ! "$player" =~ ^[a-z0-9][a-z0-9-]{0,19}$ ]]; then
  echo "usage: $0 rules|scores <player>" >&2
  exit 2
fi

account=$(aws sts get-caller-identity --query Account --output text)
case "$what" in
  rules)  target="Web ACL ${project}-${player} のルールをすべて削除 (既定のアクションは Allow に戻す)" ;;
  scores) target="DynamoDB テーブル ${project} から ${player} のスコアの記録をすべて削除" ;;
esac
echo "AWS アカウント: ${account} / リージョン: ${region}"
echo "実行する内容  : ${target}"
read -r -p "よろしいですか? [y/N] " answer
[[ "$answer" == "y" || "$answer" == "Y" ]] || { echo "中止しました"; exit 1; }

if [[ "$what" == "rules" ]]; then
  name="${project}-${player}"
  id=$(aws wafv2 list-web-acls --scope REGIONAL --region "$region" --query "WebACLs[?Name=='${name}'].Id" --output text)
  [[ -n "$id" ]] || { echo "Web ACL ${name} が見つかりません" >&2; exit 1; }
  lock=$(aws wafv2 get-web-acl --scope REGIONAL --region "$region" --name "$name" --id "$id" --query LockToken --output text)
  aws wafv2 update-web-acl --scope REGIONAL --region "$region" --name "$name" --id "$id" --lock-token "$lock" \
    --default-action Allow={} --rules '[]' \
    --visibility-config "SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=${name}" >/dev/null
  echo "Web ACL ${name} のルールを空にしました。(プレイヤーが作った IP セットなどは残っています)"
else
  pk="PLAYER#${player}"
  sks=$(aws dynamodb query --region "$region" --table-name "$project" \
    --key-condition-expression "pk = :p" --expression-attribute-values "{\":p\":{\"S\":\"${pk}\"}}" \
    --query 'Items[].sk.S' --output text)
  count=0
  for sk in $sks; do
    aws dynamodb delete-item --region "$region" --table-name "$project" \
      --key "{\"pk\":{\"S\":\"${pk}\"},\"sk\":{\"S\":\"${sk}\"}}"
    count=$((count + 1))
  done
  echo "${player} の記録を ${count} 件削除しました。"
fi
