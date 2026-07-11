# INSTALL.md — オンプレ・ネイティブインストール手順（Docker不使用）

このリポジトリは Docker を同梱していません。PostgreSQL / Python(FastAPI) / Node.js(ビルドのみ) を
直接インストールし、`systemd` でbackendを常駐、`nginx`（または Caddy）でTLS終端とリバースプロキシを行う構成です。

> **対象OS**: RHEL系（AlmaLinux 8/9/10, RHEL, Rocky Linux）を主対象にしています。
> パッケージ管理は `dnf`、ファイアウォールは `firewalld` を前提にしたコマンド例です。
> Debian/Ubuntu系の場合は `apt` / `ufw` に読み替えてください（パッケージ名はおおむね同じか近い名前です）。
>
> OpenLiteSpeed を使う場合の別手順は [docs/deploy-vps-almalinux-lsws.md](docs/deploy-vps-almalinux-lsws.md) にあります。

---

## 0. 構成概要

| コンポーネント | 役割 | 待受 |
|---|---|---|
| PostgreSQL 16 | DB | `127.0.0.1:5432`（外部公開しない） |
| backend（Python + Uvicorn、systemdサービス） | API・REST ingest・TCP ingest | `127.0.0.1:8000` + TCP `516` |
| frontend（Node.jsでビルドのみ） | 画面（静的ファイル） | nginxが配信 |
| nginx（または Caddy） | TLS終端・リバースプロキシ・静的配信 | `80`/`443` |

ポート方針:
- **公開**: 80/443（nginx）。外部の送信元機器から直接ログを送る場合のみ TCP ingestポート（既定516）も公開。
- **非公開**: backend(8000)・PostgreSQL(5432) は `127.0.0.1` バインドのみ。firewalldで開放しない。

---

## 1. 必要ソフトウェア

| ソフト | 用途 | 入手元 |
|---|---|---|
| EPEL | 補助パッケージ | `dnf install epel-release` |
| PostgreSQL 16 | DB | PGDG 公式 yum リポジトリ |
| Python 3.12 | backend 実行 | AlmaLinux AppStream（`python3.12`） |
| Node.js 24 LTS | frontend ビルド専用（本番は常駐しない） | NodeSource または AppStream |
| nginx（または Caddy） | リバースプロキシ / TLS終端 / 静的配信 | AppStream または公式リポジトリ |
| GeoLite2-Country.mmdb | GeoIP（任意） | MaxMind（手動配置。[docs/geoip.md](docs/geoip.md)） |

```bash
sudo dnf -y update
sudo dnf -y install epel-release dnf-plugins-core git curl tar

# PostgreSQL 公式リポジトリ（PGDG）
sudo dnf -y install https://download.postgresql.org/pub/repos/yum/reporpms/EL-$(rpm -E %rhel)-x86_64/pgdg-redhat-repo-latest.noarch.rpm
# AppStream同梱のpostgresqlモジュールを無効化（PGDGパッケージと衝突するのを防ぐ。RHEL/Rocky 8・9で必要）。
# RHEL/Rocky 10はモジュール機構(modularity)自体が廃止済みで対象が無いため「引数 postgresql を解決できません」
# と表示されて失敗するが、10では不要な手順なので `|| true` で無視してそのまま次に進めばよい（コピペのままでOK）。
sudo dnf -qy module disable postgresql || true

# Node.js 24 LTS（ビルド専用途。NodeSource推奨）
curl -fsSL https://rpm.nodesource.com/setup_24.x | sudo bash -

# nginx
sudo dnf -y install nginx
```

---

## 2. PostgreSQL のインストールと初期化

```bash
sudo dnf -y install postgresql16-server postgresql16
sudo /usr/pgsql-16/bin/postgresql-16-setup initdb
sudo systemctl enable --now postgresql-16

# DB / ユーザー作成（パスワードは必ず変更する）
sudo -u postgres psql <<'SQL'
CREATE USER loghub WITH PASSWORD 'ここを強いパスワードに変更';
CREATE DATABASE loghub OWNER loghub;
GRANT ALL PRIVILEGES ON DATABASE loghub TO loghub;
SQL
```

`/var/lib/pgsql/16/data/pg_hba.conf` にローカル接続の許可を追加（例）:
```
host    loghub    loghub    127.0.0.1/32    scram-sha-256
```
変更後: `sudo systemctl restart postgresql-16`

テーブルはbackend初回起動時に自動作成されます（マイグレーション不要、`Base.metadata.create_all`）。

---

## 3. backend（Python + FastAPI）の venv セットアップ

```bash
# コード配置
sudo mkdir -p /opt/loghub && sudo chown "$USER" /opt/loghub
git clone <YOUR_REPO_URL> /opt/loghub
# もしくは、このtarball/zipを /opt/loghub に展開

cd /opt/loghub/backend
sudo dnf -y install python3.12 python3.12-pip
python3.12 -m venv /opt/loghub/venv
/opt/loghub/venv/bin/pip install --upgrade pip
/opt/loghub/venv/bin/pip install -r requirements.txt
```

### .env の設置

```bash
cp /opt/loghub/.env.example /opt/loghub/backend/.env
# 値を編集（DATABASE_URL・LICENSE_SECRET 等。主要な環境変数は §7 参照）
```

### systemd unit（`/etc/systemd/system/loghub-backend.service`）

```ini
[Unit]
Description=LogSeeker backend (FastAPI/Uvicorn + TCP ingest)
After=network.target postgresql-16.service
Wants=postgresql-16.service

[Service]
WorkingDirectory=/opt/loghub/backend
EnvironmentFile=/opt/loghub/backend/.env
# TCP受信スレッドはプロセス内で1回だけbindするため、ワーカーは1（uvicorn単一プロセス）にする
ExecStart=/opt/loghub/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=always
User=loghub
Group=loghub

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /sbin/nologin loghub 2>/dev/null || true
sudo chown -R loghub:loghub /opt/loghub
sudo systemctl daemon-reload
sudo systemctl enable --now loghub-backend
sudo systemctl status loghub-backend
```

> **スケール時の注意**: 複数ワーカー（gunicorn等）にすると TCP ingestポートのbindが競合します。
> ワーカーを増やす場合は、TCP受信だけを別systemdサービスに分離してください
> （`ExecStart=/opt/loghub/venv/bin/python -c "from app.tcp_ingest import _serve; _serve(516)"`）。

---

## 4. frontend のビルドと静的ファイルの配置

本番は開発サーバ（`npm run dev`）ではなく、ビルド済み静的ファイルをnginxが配信します。
nginxが `/api` `/ingest` を中継するので **`VITE_API_BASE` は空**（同一オリジン）でビルドします。

```bash
cd /opt/loghub/frontend
npm install
VITE_API_BASE="" npm run build      # 生成: /opt/loghub/frontend/dist

sudo mkdir -p /var/www/loghub
sudo cp -r dist/* /var/www/loghub/
sudo chown -R nginx:nginx /var/www/loghub   # SELinux Enforcing環境の権限に合わせる
```

コード更新時は `npm run build` をやり直して `/var/www/loghub` へ再配置してください。

---

## 5. nginx でのリバースプロキシ設定（443でTLS終端）

`/etc/nginx/conf.d/loghub.conf`:

```nginx
# 80番はHTTPS化前の暫定 or ACME challenge用。TLS設定後は443へリダイレクトに変更する。
server {
    listen 80;
    server_name your-domain.example.com;

    # Let's Encrypt の HTTP-01 challenge 用（certbot --nginx 使用時は自動追記される）
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name your-domain.example.com;

    ssl_certificate     /etc/letsencrypt/live/your-domain.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.example.com/privkey.pem;

    client_max_body_size 50m;

    # ingest（機器/連携からの送信）→ backend。認証は INGEST_TOKEN(Bearer) で行う。
    location /ingest {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }

    # API / health → backend 直結
    location ~ ^/(api|health) {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }

    # それ以外 → フロントエンド静的ビルド（SPA。存在しないパスは index.html にフォールバック）
    root /var/www/loghub;
    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

証明書取得（certbot、AlmaLinux/RHEL系の例）:
```bash
sudo dnf -y install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.example.com
```

設定確認・反映:
```bash
sudo nginx -t
sudo systemctl enable --now nginx
sudo systemctl reload nginx
```

### 代替: Caddy を使う場合

Caddy は自動でLet's EncryptのTLS証明書を取得・更新するため、設定がより簡潔です。
`/etc/caddy/Caddyfile`:

```caddyfile
your-domain.example.com {
    handle /ingest* {
        reverse_proxy 127.0.0.1:8000
    }
    handle /api* {
        reverse_proxy 127.0.0.1:8000
    }
    handle /health {
        reverse_proxy 127.0.0.1:8000
    }
    handle {
        root * /var/www/loghub
        try_files {path} /index.html
        file_server
    }
}
```
```bash
sudo systemctl reload caddy
```

---

## 6. TCP ingest リスナー用のポート開放（firewalld）

外部の送信元（NXLog等）からTCP NDJSONで直接受信する場合のみ、TCP ingestポート（既定516）を開放します。
REST `/ingest` のみで運用する場合はこの手順は不要です。

```bash
# 公開: 80/443（nginx）。TCP ingestは外部送信元がある場合のみ。
sudo firewall-cmd --permanent --add-service=http --add-service=https
sudo firewall-cmd --permanent --add-port=516/tcp
sudo firewall-cmd --reload

# 8000（backend）と 5432（PostgreSQL）は開けない（127.0.0.1専用のため不要）
```

送信元IPを限定したい場合は `firewall-cmd --permanent --zone=<zone> --add-rich-rule=...` で絞り込むか、
リッチルール/ipsetで許可リストを運用してください。

SELinux（Enforcing前提）: nginxからbackend(127.0.0.1:8000)へのプロキシ接続を許可する場合、
`sudo setsebool -P httpd_can_network_connect 1` が必要になることがあります。

---

## 7. `.env` の設定箇所と主要な環境変数

`.env.example` をコピーして `/opt/loghub/backend/.env` に配置し、値を編集します（§3参照）。
systemd unitの `EnvironmentFile=` がこのファイルを読み込みます。

| 変数 | 説明 | 既定値 |
|---|---|---|
| `DATABASE_URL` | PostgreSQL接続文字列 | `postgresql+psycopg://loghub:loghub@localhost:5432/loghub` |
| `INGEST_TOKEN` | `/ingest` のBearer認証トークン。空なら認証なし。**外部公開時は必ず設定** | 空 |
| `TCP_INGEST_PORT` | TCP NDJSON受信ポート（0で無効） | `516` |
| `TCP_MAX_LINE_BYTES` | TCP受信1行あたりの最大バイト数（超過はdead_letterへ） | `1048576` |
| `MAX_INGEST_BYTES` | `/ingest` のリクエストサイズ上限 | `5242880` |
| `GEOIP_DB_PATH` | GeoLite2-Country.mmdb のパス（任意。[docs/geoip.md](docs/geoip.md)） | `backend/geoip/GeoLite2-Country.mmdb` |
| `JSON_STORE_DIR` | 取り込みJSON等の保存先の親ディレクトリ | `backend/data/json` |
| `CORS_ORIGINS` | CORS許可オリジン（カンマ区切り、`*`で全許可）。本番はフロントのオリジンに絞る | `*` |
| `LICENSE_SECRET` | ライセンスキー（データ保持期間の延長用）のHMAC署名鍵。**本番は必ず長いランダム文字列に変更**（既定値のままだと誰でもキーを偽造できる） | 開発用の弱い既定値 |
| `LICENSE_KEY` | 初回デプロイ時に種まきする保持期間延長キー（任意。空ならWeb UIの「ライセンス」画面から適用） | 空 |
| `AUTH_REQUIRED` | ログイン必須化。外部公開するなら `true` 推奨（[docs/auth.md](docs/auth.md)） | `false` |
| `ROOT_USERNAME` / `ROOT_PASSWORD` | 初回起動時にのみ作成される管理者アカウント。**公開前に変更すること** | `logseeker` / `logseeker` |
| `SESSION_HOURS` | ログインセッションの有効時間 | `12` |

> ログ種別による機能制限、及びAPIオプションの制限は撤廃済み。すべて既定で無償利用可能（[docs/licensing.md](docs/licensing.md)）。
> ライセンスキーが制御するのはデータ保持期間の延長のみ（[docs/retention.md](docs/retention.md)）。

---

## 8. 起動順序・動作確認

```bash
sudo systemctl enable --now postgresql-16 loghub-backend nginx   # (Caddy利用時は nginx の代わりに caddy)

curl -s http://127.0.0.1:8000/health              # backend単体
curl -s "https://your-domain.example.com/api/dashboard/summary"   # nginx経由でAPI
# 画面: https://your-domain.example.com/
```

取り込みの確認（REST / TCP）:
```bash
# REST
curl -X POST "https://your-domain.example.com/ingest?source=web01&source_type=web_access" \
  -H 'Content-Type: application/json' \
  -d '{"vhost":"example.com","client":"203.0.113.5","time":"2026-06-26T19:00:00+09:00","request":"GET / HTTP/1.1","status":"200"}'

# TCP NDJSON（TCP ingestポートを開放している場合）
printf '%s\n' '{"source":"web01","source_type":"web_access","vhost":"example.com","client":"203.0.113.5","request":"GET / HTTP/1.1","status":"200"}' | nc your-domain.example.com 516
```

同梱のサンプル送信スクリプト（`backend/samples/ssh_sample.json` を投入）も使えます:
```bash
./scripts/send_sample.sh    # Linux/Mac/Git Bash
./scripts/send_sample.ps1   # PowerShell
```

---

## 9. 補足

- **入力は JSON のみ**（REST `/ingest` ＋ TCP NDJSON）。送信側（NXLog等）がJSON化して送る前提。画面からのファイルアップロードは無し。
- 運用更新: コード更新 → backendは `pip install -r requirements.txt` 後 `sudo systemctl restart loghub-backend`、
  frontendは `npm run build` し直して `/var/www/loghub` に再配置。
- バックアップ対象: PostgreSQL（`pg_dump`）、`JSON_STORE_DIR` 配下、`.env`、nginx/Caddy設定。
- 公開前に必ず [docs/security.md](docs/security.md) のチェックリストを確認してください
  （認証必須化・`INGEST_TOKEN`・`LICENSE_SECRET`変更・ポート閉塞・TLS等）。
