"""脅威情報(IOC)取り込みツール。オフライン運用：フィードを data/ioc/ に置いて取り込む。

  cd backend && ../venv/bin/python -m app.tools.load_ioc --reset

入力: data/ioc/*.txt / *.csv（JSON_STORE_DIR の親ディレクトリ配下。.envで変更可）
書式（1行1件、# はコメント）:
  値のみ              -> 例: 198.51.100.23 / evil.example.com（ip/domain を自動判定）
  type,value,source,description -> 例: ip,198.51.100.23,abuse.ch,scanner

公開フィード例（手動DLして data/ioc/ へ配置）:
  abuse.ch Feodo Tracker IP blocklist, URLhaus, Spamhaus DROP など。
"""
import argparse
import csv
import ipaddress
import re
from pathlib import Path

from ..config import settings
from ..db import Base, SessionLocal, engine
from ..models import IOC

IOC_DIR = settings.JSON_STORE_DIR.parent / "ioc"   # /app/data/ioc
_DOMAIN = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def _detect_type(value: str) -> str | None:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        return "domain" if _DOMAIN.match(value) else None


def _parse_line(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = [p.strip() for p in next(csv.reader([line]))]
    if len(parts) >= 2 and parts[0].lower() in ("ip", "domain"):
        itype, value = parts[0].lower(), parts[1]
        source = parts[2] if len(parts) > 2 else None
        desc = parts[3] if len(parts) > 3 else None
    else:
        value = parts[0]
        itype = _detect_type(value)
        source, desc = (parts[1] if len(parts) > 1 else None), None
    if not itype or not value:
        return None
    return itype, value, source, desc


def main() -> None:
    ap = argparse.ArgumentParser(description="IOC (threat intel) loader")
    ap.add_argument("--reset", action="store_true", help="既存IOCを削除してから取り込む")
    ap.add_argument("--input", default=str(IOC_DIR))
    args = ap.parse_args()

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    if args.reset:
        n = db.query(IOC).delete()
        db.commit()
        print(f"[reset] 既存IOC {n} 件を削除")

    d = Path(args.input)
    if not d.exists():
        print(f"[!] IOCディレクトリがありません: {d}")
        return

    total = 0
    for path in sorted(d.glob("**/*")):
        if not path.is_file() or path.suffix.lower() not in (".txt", ".csv"):
            continue
        cnt = 0
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            rec = _parse_line(raw)
            if not rec:
                continue
            itype, value, source, desc = rec
            db.add(IOC(indicator_type=itype, value=value, source=source, description=desc))
            cnt += 1
        db.commit()
        print(f"[read] {path.name}: {cnt} 件")
        total += cnt
    db.close()
    print(f"\n完了: IOC {total} 件")


if __name__ == "__main__":
    main()
