"""【運用】Purview の監査ログ検索からエクスポートしたCSVを取り込む（Microsoft 365 監査ログ）。

APIのコネクタは過去7日分しか取れないため、それより前のログ（コネクタを設定する前の期間）を
入れるときに使う。CSVの AuditData 列（APIが返すJSONと同じ形）を1件ずつ m365_audit として取り込む。
コネクタと同じ取り込み口（m365_audit.ingest_records）を通るので、APIと重なった分はレコードの Id で除かれる。

  # 開発（Docker。CSVはコンテナから見える場所に置く）
  docker exec logseeker-backend-1 python -m app.tools.import_m365_csv /app/data/m365/audit.csv
  # 本番（ネイティブ）
  cd /opt/logseeker/backend && sudo -u logseeker ../venv/bin/python -m app.tools.import_m365_csv /path/to/audit.csv

- 何度実行しても、取り込み済みのレコードは二度入らない
- --dry-run は読めた件数・期間・未取り込みの件数を表示するだけで、書き込まない
- 5万行ちょうどのCSVは、Purviewのエクスポートの上限で期間の途中で切れている可能性がある（警告を出す）
- 1,000件ごとにcommitする（大きなファイルでもメモリを溜め込まない）
"""
import argparse
import csv
import json
import sys
from pathlib import Path

from ..db import SessionLocal
from ..m365_audit import DEDUP_RECORD, DEFAULT_SOURCE, ingest_records, seen_ids
from ..pipeline import dead_letter

BATCH = 1000
PURVIEW_EXPORT_LIMIT = 50000


def _rows(path: Path):
    csv.field_size_limit(sys.maxsize)
    with open(path, encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or "AuditData" not in reader.fieldnames:
            raise SystemExit(f"[!] {path}: AuditData 列がありません（Purviewの監査ログのCSVではないようです）")
        for i, row in enumerate(reader, start=2):  # 1行目は見出し
            yield i, row.get("AuditData") or ""


def main() -> None:
    ap = argparse.ArgumentParser(description="Purview監査ログCSV → m365_audit として取り込む")
    ap.add_argument("files", nargs="+", help="CSVファイル（複数可）")
    ap.add_argument("--source", default=DEFAULT_SOURCE, help=f"ログソース名（既定: {DEFAULT_SOURCE}。コネクタと同じ）")
    ap.add_argument("--dry-run", action="store_true", help="読み込みと件数の確認だけ（書き込まない）")
    args = ap.parse_args()

    db = SessionLocal()
    try:
        for name in args.files:
            path = Path(name)
            if not path.is_file():
                print(f"[!] ファイルがありません: {path}")
                continue
            total = stored = dup = bad = 0
            first = last = None
            batch: list[dict] = []

            def flush():
                nonlocal stored, dup
                if not batch:
                    return
                if args.dry_run:
                    ids = [str(r.get("Id")) for r in batch if r.get("Id")]
                    d = len(seen_ids(db, DEDUP_RECORD, ids))
                    stored, dup = stored + len(batch) - d, dup + d
                else:
                    s, d = ingest_records(db, batch, source=args.source, channel="file")
                    db.commit()
                    stored, dup = stored + s, dup + d
                batch.clear()

            for line, raw in _rows(path):
                total += 1
                try:
                    rec = json.loads(raw)
                    if not isinstance(rec, dict):
                        raise ValueError("JSONオブジェクトではありません")
                except ValueError as e:
                    bad += 1
                    if not args.dry_run:
                        dead_letter(db, raw[:4096], "invalid_json", f"{path.name} {line}行目: {e}",
                                    channel="file", source=args.source, source_type="m365_audit")
                    continue
                ct = str(rec.get("CreationTime") or "")
                if ct:
                    first = ct if first is None or ct < first else first
                    last = ct if last is None or ct > last else last
                batch.append(rec)
                if len(batch) >= BATCH:
                    flush()
                    print(f"  … {total:,}件", flush=True)
            flush()
            if not args.dry_run:
                db.commit()

            verb = "取り込み予定" if args.dry_run else "取り込み"
            print(f"[{path.name}] {total:,}行 / {verb} {stored:,}件 / 取り込み済みのため除外 {dup:,}件 / "
                  f"読めない行 {bad:,}件 / 期間(UTC) {first or '-'} 〜 {last or '-'}")
            if total == PURVIEW_EXPORT_LIMIT:
                print(f"  [注意] ちょうど{PURVIEW_EXPORT_LIMIT:,}行です。Purviewのエクスポート上限のため、"
                      "期間の途中で切れている可能性があります。期間を分けてエクスポートし直してください。")
    finally:
        db.close()


if __name__ == "__main__":
    main()
