"""【開発・検証用】手元の生ログを忠実に JSON 化し、本番と同じ ingest pipeline に流す補助ツール
（PROJECT.md §5.4）。本番入力は API/TCP。これはファイルから /ingest 相当へ投入するだけ。

  cd backend && ../venv/bin/python -m app.tools.load_logs --reset

- 入力: data/input 配下（JSON_STORE_DIR の親ディレクトリ。.envで変更可）
- payload は無改変で events.payload に保存し、normalized_events を派生生成。
- 変換JSON: data/json/converted_<file>.json に出力（目視確認用）。
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
from ..models import DeadLetter, Event, NormalizedEvent  # noqa: F401 (テーブル登録)
from ..pipeline import ingest_one

INPUT_DIR = settings.JSON_STORE_DIR.parent / "input"
OUTPUT_DIR = settings.JSON_STORE_DIR

# 入力相対パス → (変換種別, source, source_type)。新しいログはここに1行。
KIND_ROUTES: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"(^|/)syslog_.*", re.I), "yamaha", "yamaha", "router"),
    (re.compile(r"nas/ssl_access\.log$", re.I), "apache_access", "nas", "web_access"),
    (re.compile(r"nas/http-access\.log$", re.I), "apache_access", "nas", "web_access"),
    (re.compile(r"nas/error\.log$", re.I), "apache_error", "nas", "web_error"),
    (re.compile(r"nas/smbd\.log$", re.I), "samba", "nas", "auth"),
    (re.compile(r"nas/auth\.log$", re.I), "syslog", "nas", "nas"),
    (re.compile(r"web/logw_accesslog", re.I), "logw_access", "logw", "web_access"),
    (re.compile(r"web/logw_error", re.I), "lsws_error", "logw", "web_error"),
    (re.compile(r"web/access\.log$", re.I), "lsws_access", "litespeed", "web_access"),
    (re.compile(r"web/error\.log$", re.I), "lsws_error", "litespeed", "web_error"),
    (re.compile(r"web/stderr\.log$", re.I), "stderr", "litespeed", "application"),
    (re.compile(r"web/lsrestart\.log$", re.I), "lsrestart", "litespeed", "application"),
    # NXLog等が既にJSON化したもの（NDJSON: 1行1JSON）。payloadはそのまま。
    # source は EventDetail の source 欄に表示される（source_name は payload の Hostname から決まる）。
    (re.compile(r"(^|/)messages\.json$", re.I), "jsonl", "linux-messages", "linux"),
    (re.compile(r"(^|/)secure\.json$", re.I), "jsonl", "linux-secure", "linux"),
    (re.compile(r"(^|/)kantsuri_accesslog\.json$", re.I), "jsonl", "kantsuri", "web_access"),
    (re.compile(r"(^|/)logw_accesslog\.json$", re.I), "jsonl", "logw", "web_access"),
    (re.compile(r"(^|/)logw_error\.json$", re.I), "jsonl", "logw", "web_error"),
    (re.compile(r"\.csv$", re.I), "csv", "google_workspace", "google_workspace_audit"),
]

_SKIP = re.compile(r"^--\s*Logs begin at|^\s*$")
_SMB_HEAD = re.compile(r"^\[\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}")
_TS_HEAD = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
_DATE_HEAD = re.compile(r"^[A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d+\s")


def route_for(relpath: str):
    for pat, conv, source, stype in KIND_ROUTES:
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

    # --reset はスキーマごと作り直す（旧 events/logs テーブルが残っていても新スキーマに合わせる）
    if args.reset:
        Base.metadata.drop_all(bind=engine)
        print("[reset] 既存テーブルを drop")
    Base.metadata.create_all(bind=engine)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    input_dir = Path(args.input)
    if not input_dir.exists():
        print(f"[!] 入力ディレクトリがありません: {input_dir}")
        return

    db = SessionLocal()

    converted: dict[str, list[dict]] = {}
    stored = 0
    for path in sorted(input_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(input_dir).as_posix()
        route = route_for(rel)
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
