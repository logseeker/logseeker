"""payload(受信JSON) から、検索・集計・検知に使う値をTaxonomy KEYだけで取り出す。

旧 normalize.MAPPINGS は source_type ごとに候補キー（remote_addr / http_host / HTTPMethod 等の
Taxonomy外の別名）を並べた対応表だったが、設計書v12でイベントの表示・検索・集計は
「受信キーがTaxonomy KEYと一致したものだけを使う」に統一されたため、その対応表は廃止した。

ここでは v12 §5.2 と同じ考え方で「そのイベントでその意味を表しているTaxonomy KEY」を
優先順に走査して最初に値があったものを採る。別名の読み替えではない。
突合は大文字小文字を無視する（EventTime / EVENTTIME / eventtime は同じ）。
host と hostname のような別名は同一視しない。

イベント画面(events_api.py)が使うKEY群と同じものを使う。二重定義を避けるため、
KEYの一覧はこのモジュールを唯一の出所とする。
"""
from typing import Any

from .taxonomy_master import canonical_key

# --- 意味ごとのTaxonomy KEY（優先順）------------------------------------------
# 送信元IPを表し得るKEY
SRC_IP_KEYS = ["srcipv4", "srcipv6", "client", "sourceipaddress", "srchost", "xfwdforip"]
# 結果を表し得るKEY（audit_res は auditd の success/failed）
RESULT_KEYS = ["result", "audit_res", "eventtype", "action"]
# ユーザーを表し得るKEY
USER_KEYS = ["username", "accountname", "audit_acct", "targetusername"]
# HTTPステータス
STATUS_KEYS = ["statuscode", "status"]
# URI（request は "POST /path HTTP/1.1" 形式のリクエスト行なので、切り出しは呼び出し側で行う）
URI_KEYS = ["uri", "uri_parsed", "url", "query"]
# ドメイン/ホストの代表値（v12 §5.2 の優先順）
DOMAIN_HOST_KEYS = ["domain", "vhost", "virtualhost", "virtualdomain", "host", "hostname"]
# ホスト名（観測ホスト）
HOST_KEYS = ["hostname", "host"]
# サービス/プロセス
SERVICE_KEYS = ["service", "process", "program", "application"]
# 本文
MESSAGE_KEYS = ["message"]
# 重大度
SEVERITY_KEYS = ["severity", "level"]
# その他
QUERY_KEYS = ["query"]
PROTOCOL_KEYS = ["protocol"]
REQUEST_KEYS = ["request"]

_ALL_LISTS = {
    "SRC_IP_KEYS": SRC_IP_KEYS, "RESULT_KEYS": RESULT_KEYS, "USER_KEYS": USER_KEYS,
    "STATUS_KEYS": STATUS_KEYS, "URI_KEYS": URI_KEYS, "DOMAIN_HOST_KEYS": DOMAIN_HOST_KEYS,
    "HOST_KEYS": HOST_KEYS, "SERVICE_KEYS": SERVICE_KEYS, "MESSAGE_KEYS": MESSAGE_KEYS,
    "SEVERITY_KEYS": SEVERITY_KEYS, "QUERY_KEYS": QUERY_KEYS, "PROTOCOL_KEYS": PROTOCOL_KEYS,
    "REQUEST_KEYS": REQUEST_KEYS,
}

# 起動時にTaxonomy外KEYの混入を止める（v12 §15）。
for _n, _ks in _ALL_LISTS.items():
    _ng = [k for k in _ks if not canonical_key(k)]
    if _ng:
        raise RuntimeError(
            f"taxonomy_fields.{_n} にTaxonomy外KEYが含まれています: {_ng}。"
            "docs/taxonomy.md に定義してから taxonomy_master.py を再生成してください。")


def lower_map(payload: dict) -> dict[str, Any]:
    """KEYを小文字化した引き当て表。**受信payload自体は変更しない。**"""
    return {str(k).lower(): v for k, v in payload.items()}


def pick(lp: dict, keys: list[str]) -> str | None:
    """優先順に走査し、最初に値があったKEYの値を文字列で返す。"""
    for k in keys:
        v = lp.get(k)
        if v not in (None, ""):
            return str(v)
    return None


def class_of(lp: dict) -> str | None:
    """クラス。受信JSONの class KEY の値だけで決まる（推定はしない。v12 §3.2）。"""
    v = lp.get("class")
    return str(v) if v not in (None, "") else None
