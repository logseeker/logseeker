# セキュリティ / バージョン方針・脆弱性メモ

スタック各コンポーネントの推奨版数・既知脆弱性・更新運用。オンプレ（VPS/自社サーバ）ネイティブ構築（[INSTALL.md](../INSTALL.md)）に適用。
（最終調査: 2026-06-27）

---

## 1. ランタイム版数ポリシー

| コンポーネント | 推奨 | 状態（2026-06） | メモ |
|---|---|---|---|
| **Node.js** | **24 LTS（最新パッチ）** | 24=Active LTS / 22=Maintenance / **20=EOL(2026-04-30)** / 26=Current(非LTS) | 本プロジェクトでは**フロントのビルド時のみ**使用（本番はnginx/LiteSpeedが静的配信＝Node常駐なし）。`npm run dev`(vite dev server)は開発専用、本番公開しない。|
| **PostgreSQL** | 16.x（最新マイナー） | サポート中（17も可） | 定期 `dnf update` / イメージ再pullでパッチ適用。|
| **Python** | 3.12.x（最新パッチ） | サポート中 | `python:3.12-slim` は再ビルドで base 更新。|
| **OpenLiteSpeed** | 最新安定 | — | `dnf update openlitespeed` を定期実行。|
| **pgAdmin 4** | 最新 | — | venv の `pip install -U pgadmin4`。|

> **Node は 22 を使わない（24 LTS にする）**。本リポジトリは Docker を `node:24-bookworm-slim`、VPS手順を `setup_24.x` に更新済み。

---

## 2. Node.js 2026-06-18 セキュリティリリース（参考）

22.x / 24.x / 26.x で **12 CVE** 修正。主な HIGH：
- WebCrypto クラッシュ（2GiB 超ペイロードで停止）
- **TLS ホスト/ワイルドカード検証バイパス**（CVE-2026-48934 / 48928 / 48930）— マルチテナントの同一性確認に影響
- 権限モデルバイパス（FileHandle.utimes 等 CVE-2026-48935）
- **HTTP Response Queue Poisoning**（CVE-2026-48931）

**本プロジェクトへの影響度**：これらは Node が HTTP/TLS サーバ・クライアントとして動く前提の脆弱性。
本番は **nginx/LiteSpeed が前段**で Node は配信に出ない（静的ビルドのみ）ため**実害リスクは低**。
ただし **ビルド環境の Node も 24 の最新パッチに保つ**こと。**`npm run dev`(vite dev server) を本番公開しない**（開発専用、外部公開は静的ビルド経由）。

---

## 3. フロントエンド依存（npm）

| パッケージ | 備考・リスク |
|---|---|
| react / react-dom 18 | 安定。19 は任意。|
| vite 5 | **dev サーバに過去CVEあり**（ファイル配信系）。本番では vite を動かさない（静的ビルド配信）。`npm audit` で最新パッチへ。|
| echarts 5 / echarts-for-react | 表示用。`npm audit` 対象。|
| @tabler/core **1.0.0-beta** | プレリリース。バージョン固定し、安定版が出たら追従。|
| @tabler/icons-react 3 | 安定。|

運用：
```bash
cd frontend
npm audit                 # 既知脆弱性の確認
npm audit fix             # 後方互換の範囲で修正（--force は影響確認のうえ）
npm outdated              # 更新候補
```

---

## 4. バックエンド依存（pip）

`fastapi / uvicorn / sqlalchemy / psycopg / pydantic / pyyaml / geoip2`。バージョンは `backend/requirements.txt` で固定。

運用：
```bash
/opt/loghub/venv/bin/pip install pip-audit
/opt/loghub/venv/bin/pip-audit -r backend/requirements.txt   # 既知CVE確認
```
- `pyyaml` は `safe_load` のみ使用（任意オブジェクト生成を避ける）。
- `psycopg[binary]` は wheel 配布。定期更新でパッチ適用。

---

## 5. OS / systemd ハードニング（ネイティブ構築）

- **公開ポート最小化**：本番公開は nginx/LiteSpeed の 80/443 のみ。backend(8000)・PostgreSQL(5432) は
  `127.0.0.1` バインドに留め、firewalldでも開放しない（[INSTALL.md](../INSTALL.md) §6参照）。
- **秘密情報は `.env` / systemd `EnvironmentFile`** で渡し、リポジトリやDocumentRootに置かない。
  `.env` は配布物に含めない（`.gitignore` 済み）。パーミッションも `chmod 600` を推奨。
- **専用ユーザーで実行**：backendのsystemdサービスはroot以外の専用ユーザー（例 `loghub`）で動かす
  （[INSTALL.md](../INSTALL.md) の systemd unit例を参照）。
- **vite dev serverを本番公開しない**：`npm run dev` は開発専用。本番は `npm run build` の静的ビルドを配信する。
- OS・依存パッケージ（`dnf update` 等）とPython/Node依存（本ドキュメント §3・§4）を定期的に更新する。

---

## 6. アプリ自体のセキュリティ（実装状況）

| 項目 | 状態 |
|---|---|
| `/ingest` 認証 | `INGEST_TOKEN` 設定時に Bearer 必須（未設定=ローカル用に無効）。**外部公開時は必須化**。|
| SQL インジェクション | SQLAlchemy ORM＋バインドパラメータのみ。動的キーも値はバインド。|
| XSS | React が自動エスケープ。payload は `<pre>{JSON.stringify}</pre>` でテキスト表示（HTML挿入なし）。|
| サイズ制限 | `/ingest` に `MAX_INGEST_BYTES`。|
| 入力検証 | 不正JSONは弾き dead_letter へ。|
| TCP 516 受信 | 不正行は dead_letter。**外部送信元はファイアウォールでIP限定**。|

### 既知の要対応（本番前 TODO）
- **CORS が `allow_origins=["*"]`**（開発用）。本番はフロントのオリジンに限定する。
- **画面・参照APIに認証が無い**（MVP）。公開するならリバースプロキシ認証 or アプリ認証を追加。
- レート制限（`/ingest`）未実装。外部公開時に追加検討。
- `@tabler/core` がベータ。

---

## 7. 更新運用（推奨サイクル）

- **月次**：Node.js セキュリティリリース確認（https://nodejs.org/en/blog/vulnerability ）、`npm audit` / `pip-audit`、Dockerイメージ再pull＋スキャン、`dnf update`（VPS）。
- **四半期**：依存のマイナー/メジャー更新検討（vite, tabler 安定版, PostgreSQL マイナー）。
- CVE 速報時は該当コンポーネントを臨時更新。

---

## 8. ルール / 注意喚起 と IOC（脅威情報）

「ルール / 注意喚起」画面が、蓄積データから攻撃の兆候を検出し、**対策（推奨アクション）**つきで表示する。
- **IOC一致**（最優先）：既知の不正IP/ドメインに一致 → 「ブロック推奨」。
- **Webスキャン**：同一IPの 4xx 多発 → 該当IP遮断/WAF/レート制限。
- **認証総当たり（ユーザー/IP単位）**：認証失敗多発 → ロック/MFA/IP遮断。
- 海外アクセスは GeoIP(mmdb) 導入時に有効化（現状 country 列未配線）。

### IOC（脅威情報）の取り込み — オフライン運用
外部へ自動アクセスはしない。フィードを手動DLして `data/ioc/` に置き、取り込む：
```bash
# 例: 公開ブロックリストを data/ioc/ に配置（abuse.ch Feodo/URLhaus, Spamhaus DROP 等）
cd backend && ../venv/bin/python -m app.tools.load_ioc --reset
```
書式（1行1件・`#`コメント可）:
```
type,value,source,description     # 例: ip,1.2.3.4,abuse.ch,scanner
値のみ                            # 例: 1.2.3.4 / evil.example.com（ip/domain自動判定）
```
> `data/ioc/` 配下に上記の書式でテキストを置けば取り込める（空の状態で同梱）。実運用では abuse.ch 等の
> 公開ブロックリストや、自分の環境で観測した攻撃元IPをローカル観測サンプルとして登録するとよい。

> 注意: `load_logs --reset` は全テーブルを作り直す（IOCも消える）。**`load_logs --reset` → その後 `load_ioc`** の順で実行する。

---

## 参考
- [Node.js 2026-06-18 セキュリティリリース](https://nodejs.org/en/blog/vulnerability/june-2026-security-releases)
- [Node.js 脆弱性ブログ](https://nodejs.org/en/blog/vulnerability)
