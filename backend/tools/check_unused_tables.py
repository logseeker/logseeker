#!/usr/bin/env python3
"""未使用テーブル・デッドコードの棚卸しスクリプト（手動実行）。

実DBのテーブル一覧と、コード上のモデル定義・参照状況を突き合わせて、
「DBにあるがコードから使われていないテーブル」「モデルはあるがAPIから参照されないテーブル」
を洗い出す。CIツールではなく、大きな設計変更のたびに人が実行して目視確認するための道具。

背景: 2026-08-08、本番に旧§9.5/9.6のインシデント機能のテーブル(incidents/incident_events)が
コード削除後も残り続けていたことが、本番デプロイ直前に偶然発覚した。同種の取りこぼしを
早期に見つけるために用意した（docs/db-schema.md 0章参照）。

使い方:
    # 開発(Docker)
    docker exec logseeker-backend-1 python /app/tools/check_unused_tables.py
    # 本番(ネイティブ)
    cd /opt/logseeker && sudo -u logseeker venv/bin/python backend/tools/check_unused_tables.py

DB接続は環境変数 DATABASE_URL を使う（backend/app/config.py と同じ既定値にフォールバック）。
読み取り専用。DDL/DMLは一切実行しない。
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent / "app"

# 実行環境によっては backend/ が sys.path に無いので通す
sys.path.insert(0, str(APP_DIR.parent))


def db_tables() -> dict[str, int]:
    """実DBのテーブル名 → 実行数。

    pg_stat_user_tables.n_live_tup は ANALYZE 前だと0を返し「使われていないテーブル」に
    見えてしまう（実際に users が2行あるのに0と表示された）。棚卸しでは誤判定が致命的なので、
    多少遅くても count(*) で正確に数える。"""
    from sqlalchemy import create_engine, text

    url = os.environ.get("DATABASE_URL") or "postgresql+psycopg://logseeker:logseeker@localhost:5432/logseeker"
    engine = create_engine(url)
    with engine.connect() as conn:
        names = [r[0] for r in conn.execute(text("""
            SELECT c.relname FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind = 'r' AND n.nspname = 'public'
            ORDER BY c.relname
        """)).all()]
        # テーブル名はpg_classから取得した実在の識別子のみ（外部入力ではない）
        out = {name: int(conn.execute(text(f'SELECT count(*) FROM "{name}"')).scalar() or 0)
               for name in names}
    engine.dispose()
    return out


def model_tables() -> dict[str, str]:
    """models.py の __tablename__ → クラス名。"""
    src = (APP_DIR / "models.py").read_text(encoding="utf-8")
    out: dict[str, str] = {}
    cls = None
    for line in src.splitlines():
        m = re.match(r"\s*class\s+(\w+)\s*\(", line)
        if m:
            cls = m.group(1)
        m = re.match(r"""\s*__tablename__\s*=\s*["'](\w+)["']""", line)
        if m and cls:
            out[m.group(1)] = cls
    return out


def code_refs(class_name: str, skip: set[str]) -> int:
    """models.py 以外の app/*.py で、そのモデルクラス名が現れる回数。"""
    total = 0
    pat = re.compile(rf"\b{re.escape(class_name)}\b")
    for py in sorted(APP_DIR.glob("*.py")):
        if py.name in skip:
            continue
        total += len(pat.findall(py.read_text(encoding="utf-8")))
    return total


def main() -> int:
    tables = db_tables()
    models = model_tables()

    print("=" * 78)
    print(" テーブル棚卸し（DB実体 × コード参照）")
    print("=" * 78)
    print(f"{'テーブル':<34}{'行数':>10}  {'モデル':<26}{'参照'}")
    print("-" * 78)

    orphan_tables: list[str] = []   # DBにあるがモデル定義が無い＝削除漏れの疑い
    unused_models: list[str] = []   # モデルはあるがAPI等から参照されない
    missing_tables: list[str] = []  # モデルはあるがDBに無い

    for t in sorted(tables):
        cls = models.get(t)
        if not cls:
            orphan_tables.append(t)
            print(f"{t:<34}{tables[t]:>10}  {'(モデル定義なし)':<26}{'-'}")
            continue
        # models.py 自身と、モデルを機械的に列挙するだけの migrations.py は参照数に数えない
        n = code_refs(cls, skip={"models.py"})
        if n == 0:
            unused_models.append(f"{t} ({cls})")
        print(f"{t:<34}{tables[t]:>10}  {cls:<26}{n}")

    for t, cls in sorted(models.items()):
        if t not in tables:
            missing_tables.append(f"{t} ({cls})")

    print()
    print("=" * 78)
    print(" 要確認")
    print("=" * 78)
    if orphan_tables:
        print("■ DBに実在するが models.py に定義が無い（＝コード削除後のテーブル残骸の疑い）:")
        for t in orphan_tables:
            print(f"    - {t}  ({tables[t]}行)")
    else:
        print("■ DBに実在するが models.py に定義が無いテーブル: なし")

    print()
    if unused_models:
        print("■ モデル定義はあるが app/*.py のどこからも参照されていない（＝デッドコードの疑い）:")
        for m in unused_models:
            print(f"    - {m}")
    else:
        print("■ 参照されていないモデル: なし")

    print()
    if missing_tables:
        print("■ models.py にあるが実DBに存在しない（create_all未実行・環境ズレの疑い）:")
        for m in missing_tables:
            print(f"    - {m}")
    else:
        print("■ models.py にあるが実DBに無いテーブル: なし")

    print()
    print("※ 0行のテーブルは「まだ使われていないだけ」か「もう使われていない」かをコード側と併せて判断すること。")
    print("※ 参照数はモデルのクラス名の単純な出現回数。0でなくても実際には死んでいる経路がありうる。")
    print("※ このスクリプトは読み取り専用。削除は必ず人が判断・確認してから行うこと。")
    return 1 if (orphan_tables or unused_models or missing_tables) else 0


if __name__ == "__main__":
    raise SystemExit(main())
