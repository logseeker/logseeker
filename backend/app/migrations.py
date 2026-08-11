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
    本feature着手前から存在する§9.5/9.6の旧「調査ケース」機能（`status`/`severity`/`summary`/`owner`
    列を持つ`incidents`/`incident_events`。ケース/インシデント管理機能とは無関係な別実装）が
    残っていれば、create_all()より前に片付ける。既に片付いている、または元から
    その旧機能を経験していない新規インストールなら何もしない。

    2026-08-09、本番調査でこの旧テーブルの存在が判明し、ユーザー確認の上で「0行なら削除、
    1行でもあれば削除せず起動を止める」方針で対応した（無条件でDROPしない）。以前はこの
    旧`incidents`を`cases`へリネームして引き継ぐ実装だったが、無関係な別機能のデータを
    ケース機能へ引き継ぐ意味がないため、削除に変更した。"""
    # incidents/casesの早期returnより前に無条件で実行する（無関係な独立処理のため）。
    _drop_taxonomy_events(engine)
    with engine.begin() as conn:
        cases_exists = conn.execute(text("SELECT to_regclass('cases')")).scalar() is not None
        if cases_exists:
            return
        incidents_exists = conn.execute(text("SELECT to_regclass('incidents')")).scalar() is not None
        if not incidents_exists:
            return  # 新規インストール（旧機能未経験）。create_allが新モデル通りに作るので何もしなくてよい
        # 旧§9.5/9.6の"incidents"であることの確認（新モデルのincidentsには無いseverity列を持つ）
        is_legacy = conn.execute(text(
            "SELECT 1 FROM information_schema.columns WHERE table_name='incidents' AND column_name='severity'"
        )).first() is not None
        if not is_legacy:
            return  # 想定外だが安全側に倒す（case_id列を持つv3スキーマ等はrun()側の別関数で扱う）
        incidents_count = conn.execute(text("SELECT count(*) FROM incidents")).scalar()
        incident_events_exists = conn.execute(text("SELECT to_regclass('incident_events')")).scalar() is not None
        incident_events_count = (
            conn.execute(text("SELECT count(*) FROM incident_events")).scalar() if incident_events_exists else 0
        )
        if incidents_count or incident_events_count:
            raise RuntimeError(
                f"旧§9.5/9.6インシデント機能にデータが残っているため自動削除を中止しました"
                f"（incidents={incidents_count}行, incident_events={incident_events_count}行）。"
                "ケース/インシデント管理機能への移行前に、手動でデータの要否を確認してください。"
            )
        if incident_events_exists:
            conn.execute(text("DROP TABLE incident_events"))
        conn.execute(text("DROP TABLE incidents"))
    log.info("dropped legacy pre-v1 incidents/incident_events (§9.5/9.6, 0 rows) before create_all")


def _drop_taxonomy_events(engine) -> None:
    """フェーズ2・第2段でtaxonomy_events（旧taxonomy_normalize.pyのMapping変換型正規化）を廃止する
    （PROJECT_basic_design_revised_v10.md §4/§5。新設計は受信KEYの読み替え・コピーを禁止しており、
    Mapping変換前提だったこの構造は新設計と非適合。フェーズ2・第1段調査で他テーブルからのFK参照が
    無いことを確認済み）。incidents/incident_eventsと同じ方針で、0行なら削除、1行でもあれば
    削除せず起動を止める（念のためのデータ喪失防止。無条件でDROPしない）。"""
    with engine.begin() as conn:
        exists = conn.execute(text("SELECT to_regclass('taxonomy_events')")).scalar() is not None
        if not exists:
            return
        count = conn.execute(text("SELECT count(*) FROM taxonomy_events")).scalar()
        if count:
            raise RuntimeError(
                f"taxonomy_events にデータが残っているため自動削除を中止しました（{count}行）。"
                "削除前にデータの要否を確認してください。"
            )
        conn.execute(text("DROP TABLE taxonomy_events"))
    log.info("dropped taxonomy_events (phase2 step1, 0 rows)")


# フェーズ2・第2段（案C）: Class別の受信フィールドへの部分/式インデックス。
# PROJECT_basic_design_revised_v10.md §4/§5・docs/taxonomy.md v1.4は受信KEYの読み替え・コピーを
# 禁止しているため、events.payloadの生KEYへ直接インデックスする（フェーズ2・第1段調査レポート、
# フェーズ2・第2段ステップ2-1の絞り込み結果に基づく）。
# 自由記述系フィールド（message/Message等）は部分一致検索に式btreeが向かないため対象外
# （pg_trgm/GIN等の別方式は別途検討）。
# ->> 演算子はJSON値が文字列/数値のどちらでもテキストへ統一して返すため、型ゆらぎ（例: statusが
# 文字列/数値どちらでも届く可能性）はインデックス定義・検索クエリの双方で->>を一貫使用するだけで
# 吸収できる（CASTは不要。2026-08-11、はやしさん確認の上で採用）。
_PAYLOAD_FIELD_INDEXES = [
    # (source_type, payload key)
    ("web_access", "client"),
    ("web_access", "vhost"),
    ("web_access", "status"),
    ("web_access", "request"),
    ("linux", "Hostname"),
    ("linux", "SourceName"),
    ("linux", "Severity"),
    ("audit", "SourceIPAddress"),
    ("audit", "audit_type"),
    ("audit", "audit_res"),
    ("audit", "audit_acct"),
]


def create_payload_field_indexes(db: Session) -> None:
    """`_PAYLOAD_FIELD_INDEXES`の各(source_type, key)についてCREATE INDEX IF NOT EXISTSする。
    冪等（何度呼んでも安全）。ロールバックする場合は生成された `ix_events_payload_*` を
    個別にDROP INDEXすればよい。"""
    for source_type, key in _PAYLOAD_FIELD_INDEXES:
        idx_name = f"ix_events_payload_{source_type}_{key.lower()}"
        db.execute(text(
            f'CREATE INDEX IF NOT EXISTS {idx_name} ON events ((payload ->> \'{key}\')) '
            f"WHERE source_type = '{source_type}'"
        ))
    db.commit()
    log.info("payload field indexes ensured (%d)", len(_PAYLOAD_FIELD_INDEXES))


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
    _fix_incident_event_id_nullable(db)
    _add_user_settings_events_columns(db)
    log.info("case/incident management migrations: done.")


def _add_user_settings_events_columns(db: Session) -> None:
    """Events一覧のClass別列設定を保存する user_settings.events_columns 列（フェーズ3）。"""
    if not _table_exists(db, "user_settings"):
        return
    db.execute(text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS events_columns TEXT"))
    db.commit()


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


def _fix_incident_event_id_nullable(db: Session) -> None:
    """incidents.event_id を NOT NULL から NULL許容へ、FKを ON DELETE SET NULL へ変更する
    （models.py の Incident.event_id docstring参照。2026-08-09対応）。
    以前は NOT NULL + ON DELETE無指定(NO ACTION)だったため、インシデント化済みイベントが
    1件でもあると retention.py の保持期間クリーンアップ（1本のDELETE文で一括削除）が
    外部キー違反で丸ごと失敗していた。SET NULLにすることで、元イベントが削除されても
    インシデント本体（対応記録・監査ログ・コメント等）は残る。"""
    if not _table_exists(db, "incidents") or not _column_exists(db, "incidents", "event_id"):
        return
    db.execute(text("ALTER TABLE incidents ALTER COLUMN event_id DROP NOT NULL"))
    row = db.execute(text(
        "SELECT confdeltype FROM pg_constraint "
        "WHERE conname = 'incidents_event_id_fkey' AND conrelid = CAST('incidents' AS regclass)"
    )).first()
    if not row or row[0] != "n":  # "n" = 既に ON DELETE SET NULL 済み
        if row:
            db.execute(text("ALTER TABLE incidents DROP CONSTRAINT incidents_event_id_fkey"))
        db.execute(text(
            "ALTER TABLE incidents ADD CONSTRAINT incidents_event_id_fkey "
            "FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE SET NULL"
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
