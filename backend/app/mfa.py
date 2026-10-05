"""管理者のMFA（TOTP: Google Authenticator / Microsoft Authenticator 等）。

方針（docs/auth.md 参照）:
- パスワード認証は管理者(admin)ロール専用。管理者は **TOTPが必須**（未設定なら次回ログイン時に登録させる）。
  管理者以外はSSOのみで、MFAはIdP側に任せる。
- ログインは2段階。パスワードが正しい → セッションではなく5分有効の「MFAチャレンジ」を返す →
  6桁コード（またはリカバリーコード）が正しければセッションを発行する。
- TOTPシークレットはDBに暗号化して保存する（Fernet）。鍵はDBとは別に置く:
  env `MFA_KEY` があればそれ、無ければ `backend/.mfa_key`（初回に自動生成・パーミッション600）。
  **鍵を失うと全管理者のMFAが復号できなくなる**ので、DBバックアップとは別に鍵も保管すること。
  その場合や、管理者全員が端末を失った場合は `tools/reset_mfa.py <ユーザー名>` でリセットする。
- 総当たり対策: 1チャレンジあたり5回まで。さらにユーザー単位で連続10回失敗（成功でリセット）したら15分ロックする。
- 同じコードの再利用（盗み見たコードを有効時間内に使う）を防ぐため、最後に使ったタイムステップを記録する。
"""
import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta, timezone

import pyotp
import segno
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .config import BASE_DIR
from .models import MfaChallenge, User

ISSUER = "LogSeeker"
CHALLENGE_TTL = timedelta(minutes=5)
MAX_ATTEMPTS_PER_CHALLENGE = 5
LOCK_THRESHOLD = 10                  # この回数続けて失敗したら（成功でリセット）
LOCK_WINDOW = timedelta(minutes=15)  # この時間ロックする
RECOVERY_CODES = 10
KEY_FILE = BASE_DIR / ".mfa_key"


class MfaError(Exception):
    def __init__(self, message: str, status: int = 401, detail: str | None = None):
        super().__init__(message)
        self.message = message      # 画面に出す
        self.status = status
        self.detail = detail or message  # 監査ログに残す


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _h(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()


# ---------------- シークレットの暗号化 ----------------
_fernet: Fernet | None = None


def _cipher() -> Fernet:
    global _fernet
    if _fernet is None:
        key = os.getenv("MFA_KEY", "").strip()
        if not key:
            if not KEY_FILE.exists():
                fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(Fernet.generate_key().decode())
            key = KEY_FILE.read_text().strip()
        _fernet = Fernet(key.encode())
    return _fernet


def _encrypt(secret: str) -> str:
    return _cipher().encrypt(secret.encode()).decode()


def _decrypt(token: str) -> str:
    try:
        return _cipher().decrypt(token.encode()).decode()
    except InvalidToken:
        raise MfaError("MFAの設定を読み取れません。管理者に連絡してください", 500,
                       "TOTPシークレットを復号できない（MFA鍵が変わった可能性）")


# ---------------- 状態 ----------------
def is_required(user: User) -> bool:
    """パスワード認証のユーザー（＝管理者）はMFA必須。"""
    return (user.auth_method or "password") == "password"


def is_enabled(user: User) -> bool:
    return bool(user.totp_secret)


def reset(user: User) -> None:
    """MFAを未設定に戻す（次回ログイン時に再登録させる）。"""
    user.totp_secret = None
    user.totp_last_step = None
    user.mfa_recovery_codes = None
    user.mfa_fail_count = 0
    user.mfa_locked_until = None


# ---------------- チャレンジ（パスワード通過後〜コード入力まで） ----------------
def start_challenge(db: Session, user: User, purpose: str) -> dict:
    """パスワードが正しかった後に呼ぶ。フロントへ返す内容（mfa_token と次にやること）を返す。"""
    db.execute(delete(MfaChallenge).where(MfaChallenge.expires_at < _now()))
    token = secrets.token_urlsafe(32)
    db.add(MfaChallenge(token_hash=_h(token), user_id=user.id, purpose=purpose,
                        expires_at=_now() + CHALLENGE_TTL))
    db.commit()
    return {"mfa_token": token, "mfa": "verify" if is_enabled(user) else "setup"}


def peek(db: Session, token: str) -> MfaChallenge | None:
    """検証はせずにチャレンジを引く（監査ログに誰の試行かを残すため）。"""
    return db.execute(select(MfaChallenge).where(MfaChallenge.token_hash == _h(token or ""))).scalar_one_or_none()


def _load(db: Session, token: str) -> tuple[MfaChallenge, User]:
    ch = db.execute(select(MfaChallenge).where(MfaChallenge.token_hash == _h(token or ""))).scalar_one_or_none()
    if ch is None or _aware(ch.expires_at) < _now():
        raise MfaError("確認の有効期限が切れました。もう一度ログインしてください", 401, "MFAチャレンジが無効・期限切れ")
    user = db.get(User, ch.user_id)
    if user is None or not user.enabled or not is_required(user):
        raise MfaError("確認の有効期限が切れました。もう一度ログインしてください", 401, "ユーザーが無効")
    return ch, user


def _check_lock(user: User) -> None:
    until = _aware(user.mfa_locked_until)
    if until and until > _now():
        mins = max(1, int((until - _now()).total_seconds() // 60) + 1)
        raise MfaError(f"確認コードの誤りが続いたため、一時的にロックしています。約{mins}分後にお試しください",
                       429, "MFAロック中")


def _fail(db: Session, ch: MfaChallenge, user: User, detail: str) -> MfaError:
    ch.attempts += 1
    user.mfa_fail_count = (user.mfa_fail_count or 0) + 1
    locked = user.mfa_fail_count >= LOCK_THRESHOLD
    if locked:
        user.mfa_locked_until = _now() + LOCK_WINDOW
        user.mfa_fail_count = 0
    if ch.attempts >= MAX_ATTEMPTS_PER_CHALLENGE or locked:
        db.delete(ch)  # このチャレンジは使えなくする（パスワードからやり直し）
    db.commit()
    if locked:
        return MfaError("確認コードの誤りが続いたため、15分間ロックしました", 429, detail + "（ロック）")
    return MfaError("確認コードが正しくありません", 401, detail)


def _match_totp(secret: str, code: str, last_step: int | None) -> int | None:
    """一致したタイムステップを返す（前後30秒のずれまで許容）。使用済みのステップは不一致扱い。"""
    totp = pyotp.TOTP(secret)
    now_step = int(_now().timestamp()) // totp.interval
    for step in (now_step, now_step - 1, now_step + 1):
        if last_step is not None and step <= last_step:
            continue
        if secrets.compare_digest(totp.at(step * totp.interval), code):
            return step
    return None


def _normalize(code: str) -> str:
    return "".join((code or "").split()).replace("-", "").lower()


def verify(db: Session, token: str, code: str) -> tuple[User, str, bool]:
    """コードを確認する。成功したら (ユーザー, チャレンジの用途, リカバリーコードを使ったか) を返す。"""
    ch, user = _load(db, token)
    _check_lock(user)
    if not is_enabled(user):
        raise MfaError("MFAが未設定です。もう一度ログインしてください", 400, "MFA未設定でverify")
    c = _normalize(code)
    used_recovery = False
    if c.isdigit() and len(c) == 6:
        step = _match_totp(_decrypt(user.totp_secret), c, user.totp_last_step)
        if step is None:
            raise _fail(db, ch, user, "確認コード不一致")
        user.totp_last_step = step
    else:
        codes = json.loads(user.mfa_recovery_codes or "[]")
        if _h(c) not in codes:
            raise _fail(db, ch, user, "リカバリーコード不一致")
        codes.remove(_h(c))  # 一回限り
        user.mfa_recovery_codes = json.dumps(codes)
        used_recovery = True
    user.mfa_fail_count = 0
    purpose = ch.purpose
    db.delete(ch)
    db.commit()
    return user, purpose, used_recovery


def remaining_recovery_codes(user: User) -> int:
    return len(json.loads(user.mfa_recovery_codes or "[]"))


# ---------------- 登録（初回 / リセット後） ----------------
def setup_start(db: Session, token: str) -> dict:
    """新しいシークレットを作り、QRコードと手入力用のキーを返す（まだ有効化しない）。"""
    ch, user = _load(db, token)
    if is_enabled(user):
        raise MfaError("MFAは設定済みです。もう一度ログインしてください", 400, "設定済みでsetup")
    secret = pyotp.random_base32()
    ch.pending_secret = _encrypt(secret)
    db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name=ISSUER)
    qr = segno.make(uri, error="m")
    svg = qr.svg_data_uri(scale=5, border=2)
    return {"secret": secret, "otpauth_uri": uri, "qr_svg": svg}


def setup_confirm(db: Session, token: str, code: str) -> tuple[User, str, list[str]]:
    """アプリに表示されたコードで登録を確定する。(ユーザー, 用途, リカバリーコード平文) を返す。"""
    ch, user = _load(db, token)
    _check_lock(user)
    if is_enabled(user) or not ch.pending_secret:
        raise MfaError("登録をやり直してください", 400, "pending_secretなしでconfirm")
    secret = _decrypt(ch.pending_secret)
    step = _match_totp(secret, _normalize(code), None)
    if step is None:
        raise _fail(db, ch, user, "MFA登録時の確認コード不一致")
    recovery = ["-".join([secrets.token_hex(2), secrets.token_hex(2), secrets.token_hex(2)]) for _ in range(RECOVERY_CODES)]
    user.totp_secret = ch.pending_secret
    user.totp_last_step = step
    user.mfa_recovery_codes = json.dumps([_h(_normalize(r)) for r in recovery])
    user.mfa_fail_count = 0
    user.mfa_locked_until = None
    purpose = ch.purpose
    db.delete(ch)
    db.commit()
    return user, purpose, recovery
