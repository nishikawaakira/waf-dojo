"""Print terraform output -json player_access in a readable form, one block per player."""
import json
import sys

data = json.load(sys.stdin)
for player, v in data.items():
    print(f"=== {player} ===")
    print(f"  Game URL         : {v['game_url']}")
    print(f"  Console sign-in  : {v['console_signin']}")
    print(f"  IAM user name    : {v['console_user']}")
    print(f"  Password         : {v['console_pass']}")
    print(f"  WAF console      : {v['waf_console']}")
    print(f"  Web ACL          : {v['web_acl']}")
    if v.get("cf_web_acl"):
        print(f"  Web ACL (CloudFront): {v['cf_web_acl']}  (in the WAF console, choose the Global (CloudFront) region)")
    print(f"  Name prefix for IP sets etc.: {v['ipset_prefix']}")
    print()
