"""ライセンスキー発行（ベンダー側で実行）。HMAC署名付き。LICENSE_SECRET を共有しているインスタンスで検証可能。

  cd backend && ../venv/bin/python -m app.tools.issue_license --tier 3 --api --name "ACME" --days 365

保持期間の拡張（既定は全Tier共通90日）は --retention-days で指定する。
拡張ライセンスも tier/api を引き継いで「完全な状態」として再発行する（最新1件のみが有効なため）:

  ../venv/bin/python -m app.tools.issue_license --tier 4 --api --name "ACME" \
      --days 365 --retention-days 365          # 1年保持
  ../venv/bin/python -m app.tools.issue_license --tier 4 --api --name "ACME" \
      --days 365 --retention-days -1           # 無制限保持（DBから自動削除しない）
"""
import argparse
import time

from ..license import TIERS, issue_key


def main() -> None:
    ap = argparse.ArgumentParser(description="issue a signed license key")
    ap.add_argument("--tier", type=int, required=True, choices=[1, 2, 3, 4])
    ap.add_argument("--api", action="store_true", help="APIオプション(コネクタ取得)を有効化")
    ap.add_argument("--name", default=None, help="ライセンシー名")
    ap.add_argument("--days", type=int, default=0, help="有効日数（0=無期限）")
    ap.add_argument("--retention-days", type=int, default=None,
                    help="データ保持日数の上書き（未指定=既定90日 / -1=無制限）。例: 365, 1095, -1")
    args = ap.parse_args()

    payload = {"name": args.name, "tier": args.tier, "api": args.api, "iat": int(time.time())}
    if args.days > 0:
        payload["exp"] = int(time.time()) + args.days * 86400
    if args.retention_days is not None:
        payload["retention_days"] = args.retention_days

    ret_desc = ("既定90日" if args.retention_days is None
                else "無制限" if args.retention_days == -1 else f"{args.retention_days}日")
    print(f"# tier {args.tier} ({TIERS[args.tier]['name']}) / api={args.api} / "
          f"{'無期限' if not args.days else str(args.days)+'日'} / 保持期間={ret_desc}")
    print(issue_key(payload))


if __name__ == "__main__":
    main()
