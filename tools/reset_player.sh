#!/usr/bin/env bash
# Empty a player's Web ACL rules (rules), or delete their score records (scores).
#   Usage: tools/reset_player.sh rules  player1
#           tools/reset_player.sh scores player1
# Shows the target AWS account and asks for confirmation before doing anything.
set -euo pipefail

what="${1:-}"; player="${2:-}"
project="${PROJECT:-wafdojo}"; region="${REGION:-ap-northeast-1}"
if [[ ! "$what" =~ ^(rules|scores)$ || ! "$player" =~ ^[a-z0-9][a-z0-9-]{0,19}$ ]]; then
  echo "usage: $0 rules|scores <player>" >&2
  exit 2
fi

account=$(aws sts get-caller-identity --query Account --output text)
case "$what" in
  rules)  target="Delete all rules in Web ACL ${project}-${player} (default action back to Allow)" ;;
  scores) target="Delete all score records of ${player} from DynamoDB table ${project}" ;;
esac
echo "AWS account: ${account} / Region: ${region}"
echo "Action     : ${target}"
read -r -p "Continue? [y/N] " answer
[[ "$answer" == "y" || "$answer" == "Y" ]] || { echo "Aborted."; exit 1; }

if [[ "$what" == "rules" ]]; then
  name="${project}-${player}"
  id=$(aws wafv2 list-web-acls --scope REGIONAL --region "$region" --query "WebACLs[?Name=='${name}'].Id" --output text)
  [[ -n "$id" ]] || { echo "Web ACL ${name} not found" >&2; exit 1; }
  lock=$(aws wafv2 get-web-acl --scope REGIONAL --region "$region" --name "$name" --id "$id" --query LockToken --output text)
  aws wafv2 update-web-acl --scope REGIONAL --region "$region" --name "$name" --id "$id" --lock-token "$lock" \
    --default-action Allow={} --rules '[]' \
    --visibility-config "SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=${name}" >/dev/null
  echo "Emptied the rules of Web ACL ${name}. (IP sets and other resources the player created are kept.)"
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
  echo "Deleted ${count} record(s) of ${player}."
fi
