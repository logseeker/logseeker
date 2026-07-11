"""ライセンスキー発行（ベンダー側で実行）。HMAC署名付き。LICENSE_SECRET を共有しているインスタンスで検証可能。
Tier/APIオプションによる機能制限は撤廃済みのため、本ツールは実質的にデータ保持期間（既定90日）の
延長にのみ使う。発行payloadの tier/api は固定値（1/False）を自動設定する。

  cd backend && ../venv/bin/python -m app.tools.issue_license --name "ACME" --days 365

保持期間の拡張は --retention-days で指定する:

  ../venv/bin/python -m app.tools.issue_license --name "ACME" \
      --days 365 --retention-days 365          # 1年保持
  ../venv/bin/python -m app.tools.issue_license --name "ACME" \
      --days 365 --retention-days -1           # 無制限保持（DBから自動削除しない）
"""
import argparse
import time

from ..license import issue_key


def main() -> None:
    ap = argparse.ArgumentParser(description="issue a signed license key (データ保持期間の延長用)")
    ap.add_argument("--name", default=None, help="ライセンシー名")
    ap.add_argument("--days", type=int, default=0, help="有効日数（0=無期限）")
    ap.add_argument("--retention-days", type=int, default=None,
                    help="データ保持日数の上書き（未指定=既定90日 / -1=無制限）。例: 365, 1095, -1")
    args = ap.parse_args()

    # tier/api によるログ種別・APIオプションの機能制限は撤廃済み。
    # 発行キーには固定値（tier=1, api=False）を設定する（DBスキーマ・将来のTier復活に備えて維持）。
    payload = {"name": args.name, "tier": 1, "api": False, "iat": int(time.time())}
    if args.days > 0:
        payload["exp"] = int(time.time()) + args.days * 86400
    if args.retention_days is not None:
        payload["retention_days"] = args.retention_days

    ret_desc = ("既定90日" if args.retention_days is None
                else "無制限" if args.retention_days == -1 else f"{args.retention_days}日")
    print(f"# {'無期限' if not args.days else str(args.days)+'日'} / 保持期間={ret_desc}")
    print(issue_key(payload))


if __name__ == "__main__":
    main()
