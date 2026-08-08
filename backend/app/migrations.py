"""起動時に1回だけ流す冪等マイグレーション。

このプロジェクトに Alembic 等のマイグレーション機構は無く、`main.py` の起動処理が
`Base.metadata.create_all(bind=engine)` を呼ぶだけになっている（新規テーブルは自動作成されるが、
既存テーブルへのカラム追加・リネーム・制約追加は自動化されない）。ここに冪等なDDLをまとめる。
全関数は何度実行しても安全（起動のたび呼ばれる）。

設計書v2（ケース／インシデントの二層構造）で、v1の `incidents` テーブルは `cases` へ改名し、
新しい `incidents` テーブルを作り直した。**このリネームは `create_all()` より前に行う必要がある**
（`create_all()`は既存テーブルを一切変更しないが、"incidents"という名前が空いてさえいれば
新モデル通りに新規作成してくれる。逆に言うと、先に `create_all()` を走らせてしまうと
"cases"という空テーブルを先回りして作られてしまい、後から「casesが存在する＝リネーム済み」と
誤判定してv1データの移行そのものをスキップしてしまう）。そのため `pre_create_all(engine)` を
`main.py` の `Base.metadata.create_all(bind=engine)` より前に呼び出すこと。
"""
import logging

from sqlalchemy import text
from sqlalchemy.orm import Session

log = logging.getLogger("app")

# デフォルトステータス（指示書3-1→設計書v2 4-2節）。special_type で「未対応/完了/再オープン」を識別する。
DEFAULT_STATUSES = [
    # (name, special_type, sort_order)
    ("未対応", "unassigned", 1),
    ("調査中", None, 2),
    ("対応中", None, 3),
    ("様子見", None, 4),
    ("報告", None, 5),
    ("完了", "done", 6),
    ("再オープン", "reopened", 7),
]

# 既定の対応アクション種別（設計書v2 4-4節）
DEFAULT_RESPONSE_ACTION_TYPES = ["IPブロック", "パッチ適用", "ユーザー無効化", "エスカレーション", "その他"]


def pre_create_all(engine) -> None:
    """`Base.metadata.create_all(bind=engine)` より前に呼ぶこと（モジュールdocstring参照）。
    v1の incidents/incident_events/incident_comments を cases/case_events/case_comments へ改名する。
    既に改名済み、または元からv1を経験していない新規インストールなら何もしない。"""
    with engine.begin() as conn:
        cases_exists = conn.execute(text("SELECT to_regclass('cases')")).scalar() is not None
        if cases_exists:
            return
        incidents_exists = conn.execute(text("SELECT to_regclass('incidents')")).scalar() is not None
        if not incidents_exists:
            return  # 新規インストール（v1未経験）。create_allが新モデル通りに作るので何もしなくてよい
        # v1の"incidents"であることの確認（新モデルのincidentsには無いseverity列を持つ）
        is_v1 = conn.execute(text(
            "SELECT 1 FROM information_schema.columns WHERE table_name='incidents' AND column_name='severity'"
        )).first() is not None
        if not is_v1:
            return  # 想定外だが安全側に倒す
        conn.execute(text("ALTER TABLE incidents RENAME TO cases"))
        conn.execute(text("ALTER TABLE incident_events RENAME TO case_events"))
        conn.execute(text("ALTER TABLE case_events RENAME COLUMN incident_id TO case_id"))
        conn.execute(text("ALTER TABLE incident_comments RENAME TO case_comments"))
        conn.execute(text("ALTER TABLE case_comments RENAME COLUMN incident_id TO case_id"))
        # 索引はテーブルリネームで自動改名されず旧名のまま残るため、直後に create_all() が
        # 新モデル通りの"incidents"/"incident_comments"テーブルを作る際、索引名の衝突
        # （例: 旧"incidents"→"cases"に残った ix_incidents_assignee_user_id と、新incidentsが
        # 作ろうとする同名索引）でエラーになる。ここで明示的にリネームしておく。
        for old, new in (
            ("ix_incidents_status_id", "ix_cases_status_id__legacy"),
            ("ix_incidents_assignee_user_id", "ix_cases_assignee_user_id"),
            ("ix_incident_events_incident_id", "ix_case_events_case_id"),
            ("ix_incident_events_event_id", "ix_case_events_event_id"),
            ("ix_incident_comments_incident_id", "ix_case_comments_case_id"),
            ("ix_incident_comments_created_at", "ix_case_comments_created_at"),
        ):
            conn.execute(text(f"ALTER INDEX IF EXISTS {old} RENAME TO {new}"))
    log.info("renamed v1 incident tables -> cases/case_events/case_comments (pre-create_all)")


def run(db: Session) -> None:
    _drop_case_legacy_columns(db)
    _dedupe_and_constrain_case_events(db)
    _add_events_resolved_column(db)
    _seed_statuses(db)
    _seed_response_action_types(db)
    _truncate_and_refix_incident_history_fks(db)
    _migrate_incidents_case_to_event(db)
    _drop_case_verdict_assignee(db)
    _fix_user_fk_ondelete(db)
    log.info("case/incident management migrations: done.")


def _table_exists(db: Session, name: str) -> bool:
    return db.execute(text("SELECT to_regclass(:n)"), {"n": name}).scalar() is not None


def _column_exists(db: Session, table: str, column: str) -> bool:
    row = db.execute(text(
        "SELECT 1 FROM information_schema.columns WHERE table_name=:t AND column_name=:c"
    ), {"t": table, "c": column}).first()
    return row is not None


def _drop_case_legacy_columns(db: Session) -> None:
    """ケースはステータス・severity・summary・owner を持たない（設計書v2 3章）。"""
    for col in ("status", "status_id", "severity", "summary", "owner"):
        db.execute(text(f"ALTER TABLE cases DROP COLUMN IF EXISTS {col}"))
    db.commit()


def _drop_case_verdict_assignee(db: Session) -> None:
    """ケースは判定結果(verdict)・担当者(assignee_user_id)も持たない（設計書v4 3章。
    「ケースがインシデントに昇格する」という直列の関係を廃止したため、ケース側の判定結果・
    担当者は不要になった）。"""
    for col in ("assignee_user_id", "verdict"):
        db.execute(text(f"ALTER TABLE cases DROP COLUMN IF EXISTS {col}"))
    db.commit()


def _migrate_incidents_case_to_event(db: Session) -> None:
    """v3までの incidents.case_id を incidents.event_id へ置き換える（設計書v4 4.1節）。
    ケース起点のインシデントを機械的にイベント単位へ変換する妥当な規則が無いため、既存データは
    クリアしてから列を作り直す（2026-08-09、ユーザー確認の上で実施。設計書v4 0章参照）。
    新規インストール（v3を経験していない）では最初から新モデル通りevent_idで作られるため、
    このブロックはスキップされる。"""
    if _column_exists(db, "incidents", "case_id"):
        db.execute(text("DELETE FROM incidents"))
        db.execute(text("ALTER TABLE incidents DROP CONSTRAINT IF EXISTS incidents_case_id_fkey"))
        db.execute(text("ALTER TABLE incidents DROP COLUMN case_id"))
        db.execute(text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS event_id INTEGER"))
        db.execute(text("ALTER TABLE incidents ALTER COLUMN event_id SET NOT NULL"))
        db.commit()
    if not db.execute(text(
        "SELECT 1 FROM pg_constraint WHERE conname = 'uq_incidents_event_id'"
    )).first():
        db.execute(text("ALTER TABLE incidents ADD CONSTRAINT uq_incidents_event_id UNIQUE (event_id)"))
    if not db.execute(text(
        "SELECT 1 FROM pg_constraint WHERE conname = 'incidents_event_id_fkey'"
    )).first():
        db.execute(text(
            "ALTER TABLE incidents ADD CONSTRAINT incidents_event_id_fkey FOREIGN KEY (event_id) REFERENCES events(id)"
        ))
    db.commit()


def _dedupe_and_constrain_case_events(db: Session) -> None:
    if not _table_exists(db, "case_events"):
        return
    db.execute(text("""
        DELETE FROM case_events a USING case_events b
        WHERE a.id < b.id AND a.case_id = b.case_id AND a.event_id = b.event_id
    """))
    exists = db.execute(text(
        "SELECT 1 FROM pg_constraint WHERE conname IN ('uq_case_event', 'uq_incident_event')"
    )).first()
    if not exists:
        db.execute(text(
            "ALTER TABLE case_events ADD CONSTRAINT uq_case_event UNIQUE (case_id, event_id)"
        ))
    db.commit()


def _add_events_resolved_column(db: Session) -> None:
    db.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS resolved BOOLEAN NOT NULL DEFAULT false"))
    db.commit()


def _seed_statuses(db: Session) -> None:
    from .models import IncidentStatus
    if db.execute(text("SELECT 1 FROM incident_statuses LIMIT 1")).first():
        return
    for name, special_type, sort_order in DEFAULT_STATUSES:
        db.add(IncidentStatus(name=name, special_type=special_type, sort_order=sort_order))
    db.commit()


def _seed_response_action_types(db: Session) -> None:
    from .models import IncidentResponseActionType
    if db.execute(text("SELECT 1 FROM incident_response_action_types LIMIT 1")).first():
        return
    for i, name in enumerate(DEFAULT_RESPONSE_ACTION_TYPES, start=1):
        db.add(IncidentResponseActionType(name=name, sort_order=i))
    db.commit()


def _truncate_and_refix_incident_history_fks(db: Session) -> None:
    """v1時代の incident_status_history / incident_audit_log は"ケース"に対する試験操作の記録で、
    新モデルの意味論（インシデントの遷移履歴・監査ログ）とは対応しないため、ユーザー確認の上でTRUNCATEし、
    incident_id の参照先を新しい incidents テーブルへ張り替える（リネームで incidents→cases に
    なった際、既存FKは自動的に cases を指すようになってしまっているため、明示的に付け替えが必要）。"""
    for table, constraint in (
        ("incident_status_history", "incident_status_history_incident_id_fkey"),
        ("incident_audit_log", "incident_audit_log_incident_id_fkey"),
    ):
        if not _table_exists(db, table):
            continue
        row = db.execute(text(
            "SELECT confrelid::regclass::text FROM pg_constraint WHERE conname = :c"
        ), {"c": constraint}).first()
        if row and row[0] == "incidents":
            continue  # 既に新incidentsを指している（改修済み）
        db.execute(text(f"TRUNCATE TABLE {table}"))
        if row:
            db.execute(text(f"ALTER TABLE {table} DROP CONSTRAINT {constraint}"))
        db.execute(text(
            f"ALTER TABLE {table} ADD CONSTRAINT {constraint} "
            f"FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE"
        ))
    db.commit()


def _fix_user_fk_ondelete(db: Session) -> None:
    """users.id への任意参照(担当者/操作者)は ON DELETE SET NULL でなければ、監査ログ等が
    1件でも残っているユーザーを削除できなくなってしまう（Docker検証で実際に発生・修正）。
    新テーブル(cases/case_comments/incidents/incident_comments/incident_response_actions)は
    models.py側で最初からSET NULLで定義済みだが、CASCADE無し(NO ACTION)で作成済みの環境向けに
    制約を張り直す（v1から引き続き残る incident_status_history/incident_audit_log 分も含む）。"""
    fixes = [
        # cases.assignee_user_id はv4で削除済み（設計書v4 3章）。列が無い環境ではスキップされる。
        ("cases", "assignee_user_id", "cases_assignee_user_id_fkey", "incidents_assignee_user_id_fkey"),
        ("case_comments", "created_by", "case_comments_created_by_fkey", "incident_comments_created_by_fkey"),
        ("incident_status_history", "changed_by", "incident_status_history_changed_by_fkey", None),
        ("incident_audit_log", "actor", "incident_audit_log_actor_fkey", None),
        ("incidents", "assignee_user_id", "incidents_assignee_user_id_fkey", None),
        ("incident_comments", "created_by", "incident_comments_created_by_fkey", None),
        ("incident_response_actions", "actor", "incident_response_actions_actor_fkey", None),
    ]
    for table, column, constraint, legacy_constraint in fixes:
        if not _table_exists(db, table) or not _column_exists(db, table, column):
            continue
        # 同名の制約が別テーブルにも存在しうる（リネームで table 名だけ変わり制約名は旧名のまま
        # 残ることがあるため。例: "cases" と新設 "incidents" の両方が偶然
        # "incidents_assignee_user_id_fkey" を名乗るケース）。conrelid でテーブルを絞って一意にする。
        conname = constraint
        row = db.execute(text(
            "SELECT confdeltype FROM pg_constraint WHERE conname = :c AND conrelid = CAST(:t AS regclass)"
        ), {"c": conname, "t": table}).first()
        if not row and legacy_constraint:
            row = db.execute(text(
                "SELECT confdeltype FROM pg_constraint WHERE conname = :c AND conrelid = CAST(:t AS regclass)"
            ), {"c": legacy_constraint, "t": table}).first()
            if row:
                conname = legacy_constraint
        if row and row[0] == "n":  # 既に ON DELETE SET NULL 済み
            continue
        if row:
            db.execute(text(f"ALTER TABLE {table} DROP CONSTRAINT {conname}"))
        db.execute(text(
            f"ALTER TABLE {table} ADD CONSTRAINT {constraint} "
            f"FOREIGN KEY ({column}) REFERENCES users(id) ON DELETE SET NULL"
        ))
    db.commit()
