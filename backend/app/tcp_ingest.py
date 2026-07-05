"""TCP JSON Lines / NDJSON 受信（PROJECT.md §5.2）。1行=1JSONイベント。
REST と同じ pipeline.ingest_one に流す。不正行は dead_letter へ。送信元IPを receiver_ip に記録。
source / source_type は JSON 内に有れば使う（無ければ null）。"""
import json
import logging
import socket
import threading

from .config import settings
from .db import SessionLocal
from .pipeline import dead_letter, ingest_one

log = logging.getLogger("tcp_ingest")


def _process_line(line: str, ip: str | None) -> None:
    db = SessionLocal()
    try:
        payload = json.loads(line)
        if not isinstance(payload, dict):
            payload = {"value": payload}
        src = payload.get("source") or payload.get("_source")
        stype = payload.get("source_type") or payload.get("_source_type")
        ingest_one(db, payload, source=src, source_type=stype, channel="tcp", receiver_ip=ip)
        db.commit()
    except json.JSONDecodeError as e:
        db.rollback()
        dead_letter(db, line[:4096], "invalid_json", str(e), channel="tcp", receiver_ip=ip)
        db.commit()
    except Exception as e:  # noqa
        db.rollback()
        log.warning("tcp ingest error from %s: %s", ip, e)
    finally:
        db.close()


def _handle(conn: socket.socket, addr) -> None:
    """改行区切りで1行=1イベント。1行の最大長を制限してメモリ枯渇/DoSを防ぐ。"""
    ip = addr[0] if addr else None
    maxlen = settings.TCP_MAX_LINE_BYTES
    buf = b""
    try:
        with conn:
            conn.settimeout(120)
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    line = raw.decode("utf-8", "replace").strip()
                    if line:
                        _process_line(line, ip)
                if len(buf) > maxlen:  # 改行が来ないまま上限超過 → 破棄
                    db = SessionLocal()
                    try:
                        dead_letter(db, buf[:4096].decode("utf-8", "replace"),
                                    "line_too_long", f">{maxlen} bytes", channel="tcp", receiver_ip=ip)
                        db.commit()
                    finally:
                        db.close()
                    buf = b""
            # 残り（改行なしの最終行）
            tail = buf.decode("utf-8", "replace").strip()
            if tail and len(buf) <= maxlen:
                _process_line(tail, ip)
    except Exception as e:  # 接続単位の異常は握りつぶす
        log.warning("tcp connection error from %s: %s", ip, e)


def _serve(port: int) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(16)
    log.info("TCP NDJSON listener on :%d", port)
    while True:
        try:
            conn, addr = srv.accept()
            threading.Thread(target=_handle, args=(conn, addr), daemon=True).start()
        except Exception as e:  # noqa
            log.warning("accept error: %s", e)


def start() -> None:
    port = settings.TCP_INGEST_PORT
    if not port:
        return
    threading.Thread(target=_serve, args=(port,), daemon=True).start()
