"""環境変数から設定を読む。Docker固有の前提はコードに埋めない（env経由のみ）。"""
import os
from pathlib import Path

# backend/ ディレクトリ（このファイルの2つ上）
BASE_DIR = Path(__file__).resolve().parent.parent


class Settings:
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg://logseeker:logseeker@localhost:5432/logseeker",
    )

    # 空文字なら認証なし（ローカルデモ用）。値があるとトークン認証が有効。
    INGEST_TOKEN: str = os.getenv("INGEST_TOKEN", "").strip()

    # GeoIP mmdb の場所。存在しなければ country=null で動作。
    GEOIP_DB_PATH: str = os.getenv(
        "GEOIP_DB_PATH", str(BASE_DIR / "geoip" / "GeoLite2-Country.mmdb")
    )
    # GeoIP ASN mmdb の場所（任意）。存在しなければ asn/as_org=null で動作。
    GEOIP_ASN_DB_PATH: str = os.getenv(
        "GEOIP_ASN_DB_PATH", str(BASE_DIR / "geoip" / "GeoLite2-ASN.mmdb")
    )

    # 取り込んだ生JSONを保存する場所（bind mount される）
    JSON_STORE_DIR: Path = Path(os.getenv("JSON_STORE_DIR", str(BASE_DIR / "data" / "json")))

    # 設定ファイル（action辞書・ルール）の場所
    CONFIG_DIR: Path = BASE_DIR / "app" / "config"

    # リクエストサイズ上限（バイト）
    MAX_INGEST_BYTES: int = int(os.getenv("MAX_INGEST_BYTES", str(5 * 1024 * 1024)))

    # TCP NDJSON 受信ポート（0 で無効）
    TCP_INGEST_PORT: int = int(os.getenv("TCP_INGEST_PORT", "516"))

    # TCP受信の1行あたり最大バイト（超過は破棄→dead_letter。メモリ枯渇/DoS対策）
    TCP_MAX_LINE_BYTES: int = int(os.getenv("TCP_MAX_LINE_BYTES", str(1024 * 1024)))

    # ライセンス署名鍵（キー発行/検証のHMAC秘密）。本番は必ず変更。
    LICENSE_SECRET: str = os.getenv("LICENSE_SECRET", "logseeker-dev-license-secret")
    # 本番はここにライセンスキーを入れる（起動時にDBへ適用）。空なら既定値を使用。
    LICENSE_KEY: str = os.getenv("LICENSE_KEY", "").strip()
    # ライセンス未適用時の既定。LICENSE方針(第5条)どおり「WEBサーバーのみ(tier1)・APIオプション無効」。
    # 上位機能はライセンスキー適用(DB) か LICENSE_KEY(env) で解放する。
    LICENSE_DEFAULT_TIER: int = int(os.getenv("LICENSE_DEFAULT_TIER", "1"))
    LICENSE_DEFAULT_API: bool = os.getenv("LICENSE_DEFAULT_API", "false").lower() == "true"

    # 認証（ログイン）。既定 false＝ログイン不要（デモ）。true か Setting(auth_required) で必須化。
    AUTH_REQUIRED: bool = os.getenv("AUTH_REQUIRED", "false").lower() == "true"
    # 初回起動時に seed する管理者アカウント。ユーザーが1人もいない時のみ作成。
    ROOT_USERNAME: str = os.getenv("ROOT_USERNAME", "logseeker")
    ROOT_PASSWORD: str = os.getenv("ROOT_PASSWORD", "logseeker")
    # セッション有効時間（時間）
    SESSION_HOURS: int = int(os.getenv("SESSION_HOURS", "12"))

    # CORS 許可オリジン（カンマ区切り）。本番は自分のフロントのオリジンに絞る。
    # 既定 "*"（開発用。フロントはVite proxyで同一オリジンのためCORS不要なので絞っても通常動作に影響しない）
    CORS_ORIGINS: list[str] = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()]

    # お知らせ・更新履歴（GitHub Releasesを一次情報源とする）
    CHANGELOG_REPO: str = os.getenv("CHANGELOG_REPO", "logseeker/logseeker")
    # private repoにする場合やレート制限緩和が必要な場合のみ設定（未設定なら未認証で取得）
    CHANGELOG_GITHUB_TOKEN: str = os.getenv("CHANGELOG_GITHUB_TOKEN", "").strip()
    CHANGELOG_CACHE_HOURS: int = int(os.getenv("CHANGELOG_CACHE_HOURS", "1"))

    @property
    def auth_enabled(self) -> bool:
        return bool(self.INGEST_TOKEN)


settings = Settings()
