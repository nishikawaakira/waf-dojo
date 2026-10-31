"""terraform output -json player_access を、プレイヤーごとに見やすく表示する。"""
import json
import sys

data = json.load(sys.stdin)
for player, v in data.items():
    print(f"=== {player} ===")
    print(f"  ゲーム画面      : {v['game_url']}")
    print(f"  コンソール      : {v['console_signin']}")
    print(f"  IAM ユーザー名  : {v['console_user']}")
    print(f"  パスワード      : {v['console_pass']}")
    print(f"  WAF コンソール  : {v['waf_console']}")
    print(f"  Web ACL         : {v['web_acl']}")
    print(f"  IP セット等の名前の先頭: {v['ipset_prefix']}")
    print()
