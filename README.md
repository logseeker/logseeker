# LogSeeker（ログシーカー）

JSONログを**一切改変せずそのまま保存**し、その外側に**正規化・相関・検知**を積み上げる SIEM ライトな
ログ収集・可視化ツール。AI不使用（SQL集計のみ）。オンプレ（自社サーバ/VPS）へのネイティブ構築を前提とした配布物です
（Python + PostgreSQL + Node.js のビルド済み静的フロントエンド + nginx等のリバースプロキシ、という素の構成）。

> 重要な原則：**ログ本文は1文字も書き換えない**（証跡の信頼性のため）。`events.payload` に受信JSONをそのまま保存し、
> 検索・相関・検知に使う `normalized_events` は別テーブルへ派生生成する（PROJECT.md 参照）。

## クイックスタート

セットアップ手順は **[INSTALL.md](INSTALL.md)** を参照してください。PostgreSQLの初期化、backend(Python/FastAPI)の
venv・systemdサービス化、frontendのビルドと配置、nginxでのリバースプロキシ/TLS設定、firewalldでのポート開放、
`.env` の主要な設定項目まで一通り説明しています。

（AlmaLinux + OpenLiteSpeed の構成例は [docs/deploy-vps-almalinux-lsws.md](docs/deploy-vps-almalinux-lsws.md) にもあります）

初期管理者アカウント: `logseeker` / `logseeker`（`.env` の `ROOT_USERNAME` / `ROOT_PASSWORD` で変更可）。
既定ではログイン不要（検証用の動作）。必須化する手順は [docs/auth.md](docs/auth.md)。

## 構成

| コンポーネント | 役割 |
|---|---|
| nginx（またはCaddy等） | リバースプロキシ・TLS終端（443。`/api`,`/ingest`→backend、それ以外→frontendの静的ビルド） |
| frontend | React + TS + Vite + ECharts + Tabler UI（`npm run build` の静的ファイルを配信） |
| backend | Python + FastAPI（`/ingest`, `/api/...`、TCP:516 NDJSON受信。systemdサービスとして常駐） |
| PostgreSQL | DB（`events.payload` は JSONB で無改変保存） |

DB管理UIが必要な場合は pgAdmin 等を別途セットアップしてください（[INSTALL.md](INSTALL.md) §10、または
OpenLiteSpeed構成なら [docs/deploy-vps-almalinux-lsws.md](docs/deploy-vps-almalinux-lsws.md) §7に構築例）。

## 主な機能

- **取り込み**: REST `/ingest`（JSON/配列）、TCP 516（NDJSON、NXLog等から直接送信可）、ファイル取り込み補助ツール
- **正規化・エンティティ抽出**: IP/ユーザー/ホスト/ドメイン/MAC を相関調査用に抽出（URLパス等の非資産は含まない）
- **検知ルール**: IOC一致・Webスキャン・危険パス・認証総当たり・root SSH試行・海外アクセス・ログ未達 に加え、
  **画面から追加できるカスタムルール**（既存フィールドへの部分一致/完全一致＋件数しきい値、安全設計）
- **対応策の提示**: イベント一覧で「対応策」列をオン→検知内容ごとに具体的な遮断/設定変更アクションを表示
- **相関分析**: 同一IP/ユーザーが複数のログソース種別に横断出現する度合いをSQL集計（AI不使用）
- **脅威インテリ（IOC）**: AbuseIPDB / AlienVault OTX を定期同期しローカルDBで突合（オフライン運用可）
- **通知**: メール(SMTP) / Slack等Webhook。常に利用可
- **データ保持期間**: 既定90日で自動削除、拡張ライセンス（1年/3年/無制限）に対応
- **GeoIP**: MaxMind GeoLite2-Country（任意設置）で国コード判定・海外アクセス検知
- **ライセンス制御**: データ保持期間の延長のみを制御（ログ種別・APIオプションは常に無償利用可）。DBが正、envは初回種まきのみ
- **認証・RBAC・監査**: 任意ON。管理者/システム管理者/編集者/閲覧者の4ロール、操作は監査ログに記録
- **エクスポート**: イベント一覧をCSV/JSONで一括ダウンロード（現在の絞り込みに従う）

## ライセンスと利用範囲

本ソフトウェアはソースコードを公開しているが、著作権はサイトラボが保持する（ソース公開は著作権放棄ではない）。
セルフホストして自分（自社）のために使う分には改変は自由（Claude Code等での改変も含む）。ただし転売、
SaaS/マネージドホスティングとしての第三者提供、著作権表示の削除は禁止する。詳細は [LICENSE](LICENSE)（ドラフト）を参照。

### 無償で使える範囲（既定状態。有償対応の準備ができるまでの暫定方針）

| 項目 | 内容 |
|---|---|
| 対応ログ種別 | すべて（`web_access`/`web_error`/`auth`/`system`/`nas`/`mail`/`smb`/`windows_event`/`asset`/`router`/`firewall`等、制限なし） |
| APIオプション（M365/Google Workspace等コネクタ） | 有効（無償） |
| データ保持期間 | 既定90日（超過分は自動削除） |
| サポート | なし（セルフホスト・自己責任） |

### 正規ライセンスキーで延長できる範囲

| 項目 | 内容 |
|---|---|
| データ保持期間 | 1年・3年・無制限などに延長可（[docs/retention.md](docs/retention.md)） |
| サポート | 契約内容に応じて提供 |

> ソースを改変して保持期間の制限を外すこと自体を著作権者は歓迎する（[LICENSE](LICENSE) 第4条）。ただし
> それは自己責任のセルフホスト利用として扱われ、サポート対象外になる。

## ドキュメント一覧

作業内容に応じてこの表から該当ドキュメントを開いてください。

| ドキュメント | 内容 |
|---|---|
| [INSTALL.md](INSTALL.md) | **インストール手順**。PostgreSQL/venv/systemd/nginx/firewalld/.env/pgAdmin（Docker不使用） |
| [docs/usage.md](docs/usage.md) | **使い方マニュアル**。どんなログでも相関/検知が効くか、NXLogからTCP送信する方法など |
| [docs/auth.md](docs/auth.md) | ログイン・ユーザー管理・ロール(RBAC)・監査ログの仕組みと有効化手順 |
| [docs/sso.md](docs/sso.md) | SSO(OIDC)の実現可否・設計・実装手順（現状は設定保管のみ、実接続は今後） |
| [docs/licensing.md](docs/licensing.md) | ライセンス（データ保持期間の延長）の詳細 |
| [docs/retention.md](docs/retention.md) | データ保持期間（既定90日）と延長方法（拡張ライセンス） |
| [docs/geoip.md](docs/geoip.md) | GeoIP（国コード表示・海外アクセス検知）の有効化手順（無料） |
| [docs/threat-intel.md](docs/threat-intel.md) | 脅威インテリ（AbuseIPDB / AlienVault OTX）のAPIキー取得・連携方法 |
| [docs/security.md](docs/security.md) | 公開前に必須のセキュリティ対策（認証・ポート閉塞・秘密情報・TLS等） |
| [docs/security-and-versions.md](docs/security-and-versions.md) | 依存コンポーネントの推奨バージョン・既知脆弱性・更新運用 |
| [docs/deploy-vps-almalinux-lsws.md](docs/deploy-vps-almalinux-lsws.md) | Docker不使用でVPS(AlmaLinux+LiteSpeed)にネイティブ構築する手順 |

## API（抜粋）

| メソッド | パス | 用途 |
|---|---|---|
| POST | `/ingest`, `/ingest/{source}` | JSONをそのまま保存（Bearer認証は任意） |
| TCP | `:516` | NDJSON（1行1JSON）受信。`source_type`をJSON内に含める |
| GET | `/api/events` | イベント一覧（絞り込み・ページング） |
| GET | `/api/events/export?format=csv|json` | 現在の絞り込みで一括エクスポート |
| GET | `/api/rule-hits`, `/api/rules`, `/api/custom-rules` | 検知結果・ルール定義・カスタムルールCRUD |
| GET | `/api/correlations` | 複数ソース横断の相関分析 |
| GET/POST | `/api/auth/*`, `/api/users`, `/api/audit` | 認証・ユーザー管理・監査ログ |
| GET/POST | `/api/license`, `/api/notifications`, `/api/ioc/*` | ライセンス・通知・脅威インテリ設定 |

## 除外しているもの（`.gitignore` 済み）

- `data/input/*`, `data/json/*`, `data/ioc/*` … 実ログ・取り込みデータ（機密の可能性。ディレクトリ構造のみ同梱）
- `geoip/*.mmdb`, `backend/geoip/*.mmdb` … MaxMindのライセンス物（各自ダウンロード、[docs/geoip.md](docs/geoip.md)）
- `.env` … 実際の秘密情報（`.env.example` のみ同梱）
- `frontend/node_modules/`, `dist/` … `npm install` / `npm run build` で生成

## ディレクトリ構成（主要なもの）
- `backend/app` … FastAPIアプリ本体、`backend/app/tools` … ライセンス発行・ログ取り込み等のCLIツール
- `frontend/src` … React+TSのフロントエンドソース（`npm run build` で `frontend/dist` に静的ファイル生成）
- `data/input` … ファイル取り込み補助ツール（`load_logs`）の入力置き場（任意・開発検証用）
- `data/json` … 取り込みJSONの控え（`JSON_STORE_DIR` で変更可）
- `data/ioc` … 脅威インテリ（IOC）フィードの取り込み置き場（[docs/threat-intel.md](docs/threat-intel.md)）
