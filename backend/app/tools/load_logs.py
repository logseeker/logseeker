"""【開発・検証用】手元の生ログを忠実に JSON 化し、本番と同じ ingest pipeline に流す補助ツール
（PROJECT.md §5.4）。本番入力は API/TCP。これはファイルから /ingest 相当へ投入するだけ。

  cd backend && ../venv/bin/python -m app.tools.load_logs --reset

- 入力: data/input 配下（JSON_STORE_DIR の親ディレクトリ。.envで変更可）
- payload は無改変で events.payload に保存し、導出値は events の列へ入れる。
- 変換JSON: data/json/converted_<file>.json に出力（目視確認用）。
- どのファイルをどの source として取り込むかは、入力ディレクトリの routes.json に書く
  （環境ごとに違う内容なのでソースには持たない。data/input は git 管理外）。書式は README 参照。
"""
import argparse
import csv
import json
import re
from pathlib import Path
from typing import Iterator

from ..config import settings
from ..converters import CONVERTERS
from ..db import Base, SessionLocal, engine
from ..models import DeadLetter, Event  # noqa: F401 (テーブル登録)
from ..pipeline import ingest_one

INPUT_DIR = settings.JSON_STORE_DIR.parent / "input"
OUTPUT_DIR = settings.JSON_STORE_DIR

# 入力相対パス → (変換種別, source, source_type)。新しいログはここに1行。
ROUTES_FILE = "routes.json"


def load_routes(input_dir: Path) -> list[tuple[re.Pattern, str, str, str]]:
    """入力相対パス(正規表現) → (変換種別, source, source_type) の対応表を routes.json から読む。"""
    path = input_dir / ROUTES_FILE
    if not path.exists():
        raise SystemExit(f"[!] {path} がありません。取り込むファイルと source の対応を書いてください（README参照）")
    out = []
    for i, r in enumerate(json.loads(path.read_text(encoding="utf-8"))):
        conv = r.get("converter")
        if conv not in CONVERTERS and conv not in ("jsonl", "csv"):
            raise SystemExit(f"[!] {path} の{i + 1}件目: 不明な converter '{conv}'"
                             f"（使えるもの: jsonl, csv, {', '.join(sorted(CONVERTERS))}）")
        out.append((re.compile(r["pattern"], re.I), conv, r["source"], r["source_type"]))
    return out

_SKIP = re.compile(r"^--\s*Logs begin at|^\s*$")
_SMB_HEAD = re.compile(r"^\[\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}")
_TS_HEAD = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
_DATE_HEAD = re.compile(r"^[A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d+\s")


def route_for(relpath: str, routes: list[tuple[re.Pattern, str, str, str]]):
    for pat, conv, source, stype in routes:
        if pat.search(relpath):
            return conv, source, stype
    return None


def _merge_on(lines, is_head):
    records, cur = [], []
    for ln in lines:
        if _SKIP.match(ln):
            continue
        if is_head(ln):
            if cur:
                records.append(" ".join(cur))
            cur = [ln.strip()]
        elif cur:
            cur.append(ln.strip())
    if cur:
        records.append(" ".join(cur))
    return records


def _text_records(path: Path, conv: str) -> list[str]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if conv == "samba":
        return _merge_on(lines, lambda ln: bool(_SMB_HEAD.match(ln)))
    if conv == "stderr":
        return _merge_on(lines, lambda ln: bool(_TS_HEAD.match(ln)))
    if conv == "lsrestart":
        recs, pending = [], None
        for ln in lines:
            if _SKIP.match(ln):
                continue
            if _DATE_HEAD.match(ln):
                if pending is not None:
                    recs.append(pending)
                pending = ln.strip()
            elif pending is not None:
                recs.append(f"{pending} | {ln.strip()}")
                pending = None
            else:
                recs.append(ln.strip())
        if pending is not None:
            recs.append(pending)
        return recs
    return [ln for ln in lines if not _SKIP.match(ln)]


def iter_payloads(path: Path, conv: str) -> Iterator[dict]:
    if conv == "jsonl":  # NXLog等が既にJSON化（NDJSON）。1行=1JSONをそのまま payload に。
        for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                obj = json.loads(ln)
                yield obj if isinstance(obj, dict) else {"value": obj}
            except json.JSONDecodeError:
                continue
    elif conv == "csv":
        with open(path, encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh):
                yield {k: v for k, v in row.items() if k}
    else:
        fn = CONVERTERS[conv]
        for text in _text_records(path, conv):
            yield fn(text)


def main() -> None:
    ap = argparse.ArgumentParser(description="raw log -> payload -> ingest pipeline (faithful)")
    ap.add_argument("--reset", action="store_true", help="読み込み前に events/normalized/dead_letters を全削除")
    ap.add_argument("--input", default=str(INPUT_DIR))
    ap.add_argument("--limit", type=int, default=0,
                    help="各ファイル最大件数（0=無制限・既定）。解析時に絞りたい時だけ指定。")
    args = ap.parse_args()
    input_dir = Path(args.input)
    if not input_dir.exists():
        print(f"[!] 入力ディレクトリがありません: {input_dir}")
        return
    routes = load_routes(input_dir)  # --reset より前に読む（設定不備で中断したときにDBを消さないため）

    # --reset はスキーマごと作り直す（旧 events/logs テーブルが残っていても新スキーマに合わせる）
    if args.reset:
        Base.metadata.drop_all(bind=engine)
        print("[reset] 既存テーブルを drop")
    Base.metadata.create_all(bind=engine)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    db = SessionLocal()

    converted: dict[str, list[dict]] = {}
    stored = 0
    for path in sorted(input_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(input_dir).as_posix()
        if rel == ROUTES_FILE:
            continue
        route = route_for(rel, routes)
        if route is None:
            print(f"[skip] 対象外: {rel}")
            continue
        conv, source, stype = route
        recs = list(iter_payloads(path, conv))
        if args.limit and args.limit > 0:
            recs = recs[: args.limit]
        print(f"[read] {rel}: {len(recs)} records (source={source}, source_type={stype})")
        for payload in recs:
            converted.setdefault(rel, []).append(payload)
            ingest_one(db, payload, source=source, source_type=stype, channel="file")
            stored += 1
        db.commit()

    for rel, recs in converted.items():
        safe = re.sub(r"[^\w.-]", "_", rel)
        (OUTPUT_DIR / f"converted_{safe}.json").write_text(
            json.dumps(recs, ensure_ascii=False, indent=2), encoding="utf-8")

    db.close()
    print(f"\n完了: stored={stored}")


if __name__ == "__main__":
    main()
