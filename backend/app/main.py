"""FastAPI アプリ本体。ルータ登録・CORS・起動時テーブル作成。"""
import logging
import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from . import models  # noqa: F401  (テーブル定義をBaseに登録するため)
from .api import router as api_router
from .auth_api import router as auth_router
from .config import settings
from .db import Base, engine
from .ingest import router as ingest_router

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("app")

app = FastAPI(title="LogSeeker", version="0.1.0")

# CORS。既定 "*"（開発用）。本番は CORS_ORIGINS でフロントのオリジンに絞る。
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS or ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _init_db() -> None:
    # DB起動待ち（compose の healthcheck と二重だが念のためリトライ）
    for attempt in range(30):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            break
        except OperationalError:
            log.info("waiting for db... (%d)", attempt)
            time.sleep(2)
    # ケース/インシデント管理機能: v1テーブルのリネームはcreate_allより前に済ませる必要がある
    # （create_allが先に空の新テーブルを作ってしまうと、リネームの要否判定を誤るため。migrations.py参照）
    from . import migrations as incident_migrations
    incident_migrations.pre_create_all(engine)
    Base.metadata.create_all(bind=engine)
    log.info("DB ready, tables ensured.")
    # TCP NDJSON 受信を起動
    try:
        from .tcp_ingest import start as start_tcp
        start_tcp()
    except Exception as e:  # noqa
        log.warning("failed to start TCP listener: %s", e)
    # 初期データの用意（脅威インテリのフィード行・検知ルール既定値・ライセンスseed・初回管理者seed）。
    # 失敗してもアプリ自体は起動を続ける（後続のIOCスケジューラ起動やマイグレーションとは別に評価する）。
    try:
        from .db import SessionLocal
        _db = SessionLocal()
        try:
            from .ioc_sync import ensure_feed_rows
            ensure_feed_rows(_db)
            from .detectors import ensure_default_detectors
            ensure_default_detectors(_db)
            # env LICENSE_KEY は初回のみDBへ種まき（以後は Web UI＝DB が優先）
            from .license import seed_env_key
            if seed_env_key(_db, settings.LICENSE_KEY):
                log.info("license seeded from LICENSE_KEY env (initial)")
            # 初回のみ管理者(root)を seed（ユーザーが1人もいない時だけ）
            from .auth import bootstrap_root
            bootstrap_root(_db)
        finally:
            _db.close()
    except Exception as e:  # noqa
        log.warning("failed to seed initial data (ioc feeds / detectors / license / root user): %s", e)

    # ケース/インシデント管理機能のマイグレーション（migrations.py）。
    # 以前は上のIOC初期データ用意と同じtry/exceptに同居しており、マイグレーション失敗が
    # 「failed to start IOC scheduler」という無関係なメッセージで揉み消され、かつ後続の
    # start_ioc()も巻き添えでスキップされていた（2026-08-09、旧§9.5/9.6のALTER文失敗で発覚）。
    # DBスキーマの不整合はアプリ全体の信頼性に関わるため、専用のエラーメッセージで独立させる。
    try:
        from .db import SessionLocal
        from . import migrations as incident_migrations
        _mig_db = SessionLocal()
        try:
            incident_migrations.run(_mig_db)
        finally:
            _mig_db.close()
    except Exception as e:  # noqa
        log.error("case/incident management migration failed (schema may be inconsistent): %s", e)

    # フェーズ2・第2段（案C）: Class別受信フィールドへの部分インデックス（migrations.py参照）。
    # 上のcase/incident管理マイグレーションとは無関係な処理のため、独立したtry/exceptにする
    # （関係ない失敗が別々のマイグレーションを巻き添えにしないよう、直上と同じ方針を踏襲）。
    try:
        from .db import SessionLocal
        from . import migrations
        _idx_db = SessionLocal()
        try:
            migrations.create_payload_field_indexes(_idx_db)
        finally:
            _idx_db.close()
    except Exception as e:  # noqa
        log.error("payload field index migration failed: %s", e)

    # 脅威インテリの自動同期スケジューラ起動。上記の初期データ用意・マイグレーションの成否に
    # 関わらず必ず起動を試みる（スケジューラ自身は1周ごとにtry/exceptしており、
    # フィード行が未整備でも次回同期時に自然に解消されるため、ここで足止めする理由が無い）。
    try:
        from .ioc_scheduler import start as start_ioc
        start_ioc()
    except Exception as e:  # noqa
        log.warning("failed to start IOC scheduler: %s", e)
    # データ保持期間の自動クリーンアップ（既定90日。ライセンスで延長/無制限）
    try:
        from .retention import start as start_retention
        start_retention()
    except Exception as e:  # noqa
        log.warning("failed to start retention scheduler: %s", e)
    # 定期監視（攻撃兆候・ログ未達・カスタムルール）→通知
    try:
        from .monitor_scheduler import start as start_monitor
        start_monitor()
    except Exception as e:  # noqa
        log.warning("failed to start monitor scheduler: %s", e)


@app.get("/health")
def health():
    return {"status": "ok"}


# 監査: 変更系(POST/PUT/PATCH/DELETE)のAPI操作を記録する。
# ログイン後にユーザーが行った操作を残す目的。/ingest（機器→大量）と /auth/login（個別記録済）は除外。
_AUDIT_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_AUDIT_SKIP_PATHS = ("/api/auth/login", "/api/auth/logout")


@app.middleware("http")
async def audit_mutations(request: Request, call_next):
    response = await call_next(request)
    try:
        path = request.url.path
        if (request.method in _AUDIT_METHODS and path.startswith("/api")
                and path not in _AUDIT_SKIP_PATHS):
            from .auth import audit, client_ip, get_current_user
            from .db import SessionLocal
            db = SessionLocal()
            try:
                user = get_current_user(request.headers.get("authorization"), db)
                audit(db, action="api.change", user=user, method=request.method, path=path,
                      status=str(response.status_code),
                      ip=client_ip(request))
            finally:
                db.close()
    except Exception:  # noqa  監査失敗で本処理を壊さない
        pass
    return response


# 認証必須(ON)のとき、/api 全体でログインを強制する（読み取りAPIも含めて一括防御）。
# ログイン前でも必要な status/login は素通り。/ingest は機器用（INGEST_TOKENで別管理）。
_AUTH_OPEN_PATHS = {"/api/auth/login", "/api/auth/status", "/api/auth/admin-login"}


@app.middleware("http")
async def enforce_auth(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api") and path not in _AUTH_OPEN_PATHS:
        from .auth import get_current_user, is_auth_required
        from .db import SessionLocal
        db = SessionLocal()
        try:
            if is_auth_required(db) and get_current_user(request.headers.get("authorization"), db) is None:
                return JSONResponse({"error": "ログインが必要です"}, status_code=401)
        finally:
            db.close()
    return await call_next(request)


# 管理パネル(?screen=administration)へのアクセスそのもののIP制限（アプリ層・任意ON）。
# SSHのAllowUsers/送信元制限や、WordPress管理画面のIP制限などと同じ発想。
@app.middleware("http")
async def enforce_ip_restrict(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api"):
        from . import ip_restrict as R
        from .auth import access_control_ip, audit
        from .db import SessionLocal
        if R.is_protected_path(path):
            db = SessionLocal()
            try:
                if R.is_enabled(db):
                    ip = access_control_ip(request)
                    if not R.ip_in_allowlist(db, ip):
                        audit(db, action="ip_restrict.block", method=request.method, path=path,
                              status="403", ip=ip, detail="administration panel")
                        return JSONResponse(
                            {"error": "このネットワークからのアクセスは許可されていません", "your_ip": ip},
                            status_code=403,
                        )
            finally:
                db.close()
    return await call_next(request)


app.include_router(ingest_router)
app.include_router(auth_router)
app.include_router(api_router)
