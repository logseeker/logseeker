"""payload のキー構成から source_type を自動判定する（PROJECT.md §7.8補足）。
source_type が明示されなかった受信イベントにのみ使う。値の推定（device_name等・normalize.py）とは別ロジックで、
そちらには一切触れない。判定できなければ None を返す（pipeline側でNULLのまま保存＝従来のUnknown表示と同じ）。
"""
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import SourceTypeDetector

# auth の required/optional は normalize.py の MAPPINGS["auth"] が参照するキー
# (user/host/process/message/raw) を根拠にしているが、実データ（converters.conv_samba,
# nas/smbd.log 由来）では host/process/message は出現せず {time, user, raw} のみが実際に埋まる。
# host/process/message はMAPPINGS上は宣言されているが現行の実データでは空振りする（PROJECT.md 12.6
# には想定payloadの記載自体が無く、照合しようがなかった）。required_keys はこの実データで確実に
# 揃う user/raw のみとし、host/process/message/time/pid はNXLog側で付与された場合の加点用に
# optional_keys へ回す。
DEFAULT_DETECTORS: list[dict] = [
    {
        "source_type": "web_access",
        "required_keys": ["vhost", "client", "request", "status"],
        "optional_keys": ["time", "size", "referer", "user_agent", "raw"],
        "key_value_hints": {},
        "priority": 100,
        "weight": 1.0,
    },
    {
        "source_type": "auth",
        "required_keys": ["user", "raw"],
        "optional_keys": ["time", "host", "process", "message", "pid"],
        "key_value_hints": {},
        "priority": 100,
        "weight": 1.0,
    },
]


def ensure_default_detectors(db: Session) -> None:
    """初期ルールを投入（source_type単位で無ければ作成。既存行は変更しない）。"""
    existing = {d.source_type for d in db.execute(select(SourceTypeDetector)).scalars().all()}
    for d in DEFAULT_DETECTORS:
        if d["source_type"] not in existing:
            db.add(SourceTypeDetector(**d))
    db.commit()


def detect_source_type(db: Session, payload: dict) -> str | None:
    """payload のキー集合を有効なルールと照合し、最高スコアの source_type を返す。
    どれにも十分マッチしなければ None（= 未分類。呼び出し側でNULL保存・UIは従来通りUnknown表示）。"""
    keys = set(payload.keys())
    rules = db.execute(
        select(SourceTypeDetector)
        .where(SourceTypeDetector.enabled.is_(True))
        .order_by(SourceTypeDetector.priority)
    ).scalars().all()

    best_type, best_score = None, 0.0
    for rule in rules:
        required = set(rule.required_keys or [])
        if not required or not required.issubset(keys):
            continue  # required_keys が空、または一部でも欠けたら候補外
        score = float(len(required))
        score += sum(1 for k in (rule.optional_keys or []) if k in keys)
        for k, expected in (rule.key_value_hints or {}).items():
            v = payload.get(k)
            if v is not None and str(v) in {str(x) for x in expected}:
                score += 1
        score *= rule.weight
        if score > best_score:
            best_type, best_score = rule.source_type, score

    return best_type
