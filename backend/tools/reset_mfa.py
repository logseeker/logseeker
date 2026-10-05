#!/usr/bin/env python3
"""管理者のMFA（TOTP）をリセットする非常用スクリプト（手動実行）。

通常は画面（ユーザー管理 →「MFAリセット」）で別の管理者がリセットする。このスクリプトは
それができない場合（管理者が1人しかおらず端末とリカバリーコードを両方失った、MFA鍵
`backend/.mfa_key` を失って全員が復号できなくなった等）に、サーバーへログインできる人が使う。
リセットされたユーザーは、次回ログイン時に認証アプリの再登録を求められる。

使い方:
    # 開発(Docker)
    docker exec logseeker-backend-1 python /app/tools/reset_mfa.py <ユーザー名>
    # 本番(ネイティブ)
    cd /opt/logseeker && sudo -u logseeker env $(grep DATABASE_URL backend/.env | xargs) \\
      venv/bin/python backend/tools/reset_mfa.py <ユーザー名>

実行内容は監査ログに「MFAリセット（サーバー上のツール）」として残る。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # backend/ を import できるようにする


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    username = sys.argv[1]

    from sqlalchemy import select

    from app.auth import audit
    from app.db import SessionLocal
    from app.mfa import reset
    from app.models import User

    db = SessionLocal()
    try:
        u = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if u is None:
            print(f"ユーザーが見つかりません: {username}")
            return 1
        if (u.auth_method or "password") != "password":
            print(f"{username} はSSOユーザーです（MFAはIdP側で管理）。")
            return 1
        reset(u)
        db.commit()
        audit(db, action="user.update", status="200", username=username, role=u.role, target=username,
              detail="MFAをリセット（サーバー上のツール reset_mfa.py。次回ログイン時に再登録）")
        print(f"{username} のMFAをリセットしました。次回ログイン時に認証アプリの再登録が必要です。")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
