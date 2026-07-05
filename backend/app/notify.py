"""アラート通知（メール / Slack webhook）。
全ライセンスティアで使用可。設定はSettings DBテーブルに保存。
"""
import json
import smtplib
import urllib.request
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Setting

# ---- Setting キー定義 ----
K_EMAIL_ENABLED  = "notify_email_enabled"
K_EMAIL_HOST     = "notify_email_host"
K_EMAIL_PORT     = "notify_email_port"
K_EMAIL_USER     = "notify_email_user"
K_EMAIL_PASS     = "notify_email_pass"
K_EMAIL_FROM     = "notify_email_from"
K_EMAIL_TO       = "notify_email_to"        # カンマ区切り複数可
K_SLACK_ENABLED  = "notify_slack_enabled"
K_SLACK_WEBHOOK  = "notify_slack_webhook"
K_MIN_SEVERITY   = "notify_min_severity"    # critical/high/warning
K_LAST_NOTIFIED  = "notify_last_notified"   # ISO8601 最終通知日時

SEV_ORDER = {"critical": 0, "high": 1, "warning": 2, "info": 3}
SEV_EMOJI = {"critical": "🚨", "high": "⚠️", "warning": "⚡", "info": "ℹ️"}


def _get(db: Session, key: str, default: str = "") -> str:
    row = db.execute(select(Setting).where(Setting.key == key)).scalar_one_or_none()
    return row.value if (row and row.value is not None) else default


def _set(db: Session, key: str, value: str) -> None:
    row = db.execute(select(Setting).where(Setting.key == key)).scalar_one_or_none()
    if row:
        row.value = value
    else:
        db.add(Setting(key=key, value=value))
    db.commit()


def get_config(db: Session) -> dict:
    return {
        "email_enabled":  _get(db, K_EMAIL_ENABLED,  "false") == "true",
        "email_host":     _get(db, K_EMAIL_HOST),
        "email_port":     int(_get(db, K_EMAIL_PORT, "587")),
        "email_user":     _get(db, K_EMAIL_USER),
        "email_pass":     "***" if _get(db, K_EMAIL_PASS) else "",   # マスク
        "email_from":     _get(db, K_EMAIL_FROM),
        "email_to":       _get(db, K_EMAIL_TO),
        "slack_enabled":  _get(db, K_SLACK_ENABLED, "false") == "true",
        "slack_webhook":  _get(db, K_SLACK_WEBHOOK),
        "min_severity":   _get(db, K_MIN_SEVERITY, "high"),
        "last_notified":  _get(db, K_LAST_NOTIFIED),
    }


def save_config(db: Session, cfg: dict) -> None:
    _set(db, K_EMAIL_ENABLED, "true" if cfg.get("email_enabled") else "false")
    if cfg.get("email_host")    is not None: _set(db, K_EMAIL_HOST,    cfg["email_host"])
    if cfg.get("email_port")    is not None: _set(db, K_EMAIL_PORT,    str(cfg["email_port"]))
    if cfg.get("email_user")    is not None: _set(db, K_EMAIL_USER,    cfg["email_user"])
    if cfg.get("email_pass") and cfg["email_pass"] != "***":
        _set(db, K_EMAIL_PASS, cfg["email_pass"])
    if cfg.get("email_from")    is not None: _set(db, K_EMAIL_FROM,    cfg["email_from"])
    if cfg.get("email_to")      is not None: _set(db, K_EMAIL_TO,      cfg["email_to"])
    _set(db, K_SLACK_ENABLED, "true" if cfg.get("slack_enabled") else "false")
    if cfg.get("slack_webhook") is not None: _set(db, K_SLACK_WEBHOOK, cfg["slack_webhook"])
    if cfg.get("min_severity")  is not None: _set(db, K_MIN_SEVERITY,  cfg["min_severity"])


def send_email(to_addrs: list[str], subject: str, body: str, db: Session) -> str | None:
    """Return None on success, error string on failure."""
    host  = _get(db, K_EMAIL_HOST)
    port  = int(_get(db, K_EMAIL_PORT, "587"))
    user  = _get(db, K_EMAIL_USER)
    passwd = _get(db, K_EMAIL_PASS)
    from_  = _get(db, K_EMAIL_FROM) or user or "logseeker@localhost"
    if not host:
        return "SMTPホストが未設定です"
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = from_
        msg["To"]      = ", ".join(to_addrs)
        msg.attach(MIMEText(body, "plain", "utf-8"))
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=15) as s:
                if user: s.login(user, passwd)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as s:
                s.ehlo()
                if port != 25:
                    s.starttls()
                if user: s.login(user, passwd)
                s.send_message(msg)
        return None
    except Exception as e:
        return str(e)


def send_slack(message: str, webhook_url: str) -> str | None:
    """Slack Incoming Webhook に POST。Return None on success."""
    if not webhook_url:
        return "Webhook URLが未設定です"
    try:
        payload = json.dumps({"text": message}).encode("utf-8")
        req = urllib.request.Request(
            webhook_url, data=payload,
            headers={"Content-Type": "application/json; charset=utf-8"})
        with urllib.request.urlopen(req, timeout=10) as r:
            if r.status != 200:
                return f"HTTP {r.status}: {r.read().decode()[:200]}"
        return None
    except Exception as e:
        return str(e)


def _build_text(hits: list[dict]) -> tuple[str, str]:
    """Return (subject, body)."""
    top_sev = hits[0]["severity"] if hits else "info"
    emoji   = SEV_EMOJI.get(top_sev, "⚡")
    subject = f"{emoji} [LogSeeker] 注意喚起 {len(hits)} 件 (最高重大度: {top_sev})"
    lines   = [subject, "=" * 60, ""]
    for h in hits[:15]:
        e = SEV_EMOJI.get(h["severity"], "")
        lines.append(f"{e} [{h['severity'].upper()}] {h['title']}")
        lines.append(f"   {h['evidence']}")
        lines.append(f"   対策: {h['recommendation']}")
        lines.append("")
    if len(hits) > 15:
        lines.append(f"... 他 {len(hits) - 15} 件")
    lines.append("─" * 60)
    lines.append("LogSeeker ログシーカー | 自動通知")
    return subject, "\n".join(lines)


def notify_hits(db: Session, hits: list[dict]) -> dict:
    """ルールヒット → メール/Slack 送信。重大度フィルタ・重複送信防止つき。
    Returns {"email": "ok"|"error:...", "slack": "ok"|"error:...", "skipped": bool}"""
    if not hits:
        return {"skipped": True, "reason": "no hits"}

    min_sev = _get(db, K_MIN_SEVERITY, "high")
    filtered = [h for h in hits if SEV_ORDER.get(h["severity"], 99) <= SEV_ORDER.get(min_sev, 1)]
    if not filtered:
        return {"skipped": True, "reason": f"no hits above {min_sev}"}

    subject, body = _build_text(filtered)
    result: dict = {"skipped": False}

    email_enabled = _get(db, K_EMAIL_ENABLED) == "true"
    if email_enabled:
        to_raw = _get(db, K_EMAIL_TO)
        to_list = [a.strip() for a in to_raw.split(",") if a.strip()]
        if to_list:
            err = send_email(to_list, subject, body, db)
            result["email"] = "ok" if not err else f"error: {err}"

    slack_enabled = _get(db, K_SLACK_ENABLED) == "true"
    if slack_enabled:
        webhook = _get(db, K_SLACK_WEBHOOK)
        err = send_slack(body, webhook)
        result["slack"] = "ok" if not err else f"error: {err}"

    if result.get("email") == "ok" or result.get("slack") == "ok":
        _set(db, K_LAST_NOTIFIED, datetime.now(timezone.utc).isoformat())

    return result
