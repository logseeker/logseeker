"""ライセンスキー発行（ベンダー側で実行）。HMAC署名付き。LICENSE_SECRET を共有しているインスタンスで検証可能。
Tier/APIオプションによる機能制限は撤廃済みのため、本ツールは実質的にデータ保持期間（既定90日）の
延長にのみ使う。発行payloadの tier/api は固定値（1/False）を自動設定する。

  cd backend && ../venv/bin/python -m app.tools.issue_license --name "ACME" --days 365

保持期間の拡張は --retention-days で指定する:

  ../venv/bin/python -m app.tools.issue_license --name "ACME" \
      --days 365 --retention-days 365          # 1年保持
  ../venv/bin/python -m app.tools.issue_license --name "ACME" \
      --days 365 --retention-days -1           # 無制限保持（DBから自動削除しない）

1年・数ヶ月など「期間」単位のライセンスは --days の代わりに --months を使う。
--months 指定時は満了日をその月の末日に丸める（90日ライセンス等、日数指定の --days は丸めない）。

  ../venv/bin/python -m app.tools.issue_license --name "ACME" --months 12   # 1年、月末満了

更新（かぶせ発行）で現行ライセンスの残存期間を無駄にしたくない場合は、管理画面の「有効期限」に
表示されている日付を --start にそのまま貼り付ける（今日の日付より前でも後でも指定可）。
起点日 + --months ヶ月を計算してから月末に丸めるため、期間が重複してもよい前提で早めに
更新キーを発行できる:

  # 現行ライセンスが 2026/01/31 満了 → 2025/11/01 に1年更新を発行しても満了日は2027/01/31 になる
  ../venv/bin/python -m app.tools.issue_license --name "ACME" --months 12 --start 2026/01/31
"""
import argparse
import calendar
import time
from datetime import date, datetime, time as dtime

from ..license import issue_key


def _parse_date(s: str) -> date:
    return datetime.strptime(s.replace("/", "-"), "%Y-%m-%d").date()


def _add_months(d: date, months: int) -> date:
    month_index = d.month - 1 + months
    year = d.year + month_index // 12
    month = month_index % 12 + 1
    day = min(d.day, calendar.monthrange(year, month)[1])
    return date(year, month, day)


def _end_of_month(d: date) -> date:
    return d.replace(day=calendar.monthrange(d.year, d.month)[1])


def main() -> None:
    ap = argparse.ArgumentParser(description="issue a signed license key (データ保持期間の延長用)")
    ap.add_argument("--name", default=None, help="ライセンシー名")
    ap.add_argument("--days", type=int, default=0,
                    help="有効日数（0=無期限）。90日ライセンス等、月末丸めをしない場合はこちら")
    ap.add_argument("--months", type=int, default=0,
                    help="有効月数（例: 12=1年）。起点日+Nヶ月を、その月の末日に丸めて満了日とする")
    ap.add_argument("--start", default=None,
                    help="起点日 YYYY/MM/DD または YYYY-MM-DD（省略時は今日=インストール日）。"
                         "更新の場合は管理画面の現行の有効期限をそのまま指定すると、期間が継ぎ足される")
    ap.add_argument("--retention-days", type=int, default=None,
                    help="データ保持日数の上書き（未指定=既定90日 / -1=無制限）。例: 365, 1095, -1")
    args = ap.parse_args()

    if args.days > 0 and args.months > 0:
        raise SystemExit("--days と --months は同時に指定できません")

    start = _parse_date(args.start) if args.start else date.today()

    exp_date: date | None = None
    if args.months > 0:
        exp_date = _end_of_month(_add_months(start, args.months))
    elif args.days > 0:
        exp_date = date.fromordinal(start.toordinal() + args.days)

    # tier/api によるログ種別・APIオプションの機能制限は撤廃済み。
    # 発行キーには固定値（tier=1, api=False）を設定する（DBスキーマ・将来のTier復活に備えて維持）。
    payload = {"name": args.name, "tier": 1, "api": False, "iat": int(time.time())}
    if exp_date is not None:
        payload["exp"] = int(datetime.combine(exp_date, dtime(23, 59, 59)).timestamp())
    if args.retention_days is not None:
        payload["retention_days"] = args.retention_days

    ret_desc = ("既定90日" if args.retention_days is None
                else "無制限" if args.retention_days == -1 else f"{args.retention_days}日")
    term_desc = "無期限" if exp_date is None else f"{exp_date.isoformat()} 満了（起点 {start.isoformat()}）"
    print(f"# {term_desc} / 保持期間={ret_desc}")
    print(issue_key(payload))


if __name__ == "__main__":
    main()
