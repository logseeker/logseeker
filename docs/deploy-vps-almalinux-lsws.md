# VPS ネイティブ構築手順（AlmaLinux + LiteSpeed、Docker不使用）

Docker Compose の4サービス（`db` / `backend` / `frontend` / `pgadmin`）を、VPS 上のミドルウェアで同じ動きになるよう構築する手順。
**OS は RHEL系（AlmaLinux 8 / 9 / 10）前提**。パッケージ管理は `dnf`、Debian系（apt）は使わない。

> 中身は素の Python / Node / PostgreSQL なので、Docker を剥がしても同じ構成で動く（PROJECT.md §6.3 の方針）。

---

## 0. Docker構成 → VPSミドルウェア 対応表

| Docker サービス | 役割 | VPS でのミドルウェア |
|---|---|---|
| `db` (postgres:16) | DB | **PostgreSQL 16**（systemd: `postgresql-16`） |
| `backend` (python+FastAPI) | API / ingest / TCP受信 | **Python 3.12 + venv + Uvicorn**（systemd サービス、`127.0.0.1:8000` ＋ TCP `516`） |
| `frontend` (vite) | 画面 | **Node.js 22 でビルド**し、生成した静的ファイルを **LiteSpeed が配信** |
| （compose内のVite proxy） | /api 中継 | **LiteSpeed のリバースプロキシ**（`/api` `/ingest` `/health` → `127.0.0.1:8000`） |
| `pgadmin` | DB管理 | **pgAdmin 4（server mode）** を Gunicorn + systemd、LiteSpeed で `/pgadmin` をプロキシ |

ポート方針:
- 80/443 … LiteSpeed（画面＋API＋pgAdmin を集約）
- 8000 … backend（**127.0.0.1 のみ**。外部公開しない＝LiteSpeed経由）
- 5432 … PostgreSQL（**localhost のみ**）
- 516 … TCP NDJSON 受信（外部の送信元から送るなら firewalld で開放）

---

## 1. 必要ソフトウェア一覧

| ソフト | 用途 | 入手元（リポジトリ） |
|---|---|---|
| EPEL | 補助パッケージ | `dnf install epel-release` |
| PostgreSQL 16 | DB | PGDG 公式 yum リポジトリ |
| Python 3.12 | backend 実行 | AlmaLinux AppStream（`python3.12`） |
| Node.js 22 | frontend ビルド | AppStream（`nodejs:22`）または NodeSource |
| OpenLiteSpeed | Webサーバ/プロキシ | LiteSpeed 公式リポジトリ |
| pgAdmin 4 | DB管理画面 | pip（venv 内）※または pgAdmin 公式 RPM |
| GeoLite2-Country.mmdb | GeoIP（任意） | MaxMind（手動配置） |

---

## 2. リポジトリ登録

```bash
# 基本更新 + EPEL + 開発ツール
sudo dnf -y update
sudo dnf -y install epel-release dnf-plugins-core git curl tar

# PostgreSQL 公式リポジトリ（PGDG）。$releasever は 8/9/10 に解決される
sudo dnf -y install https://download.postgresql.org/pub/repos/yum/reporpms/EL-$(rpm -E %rhel)-x86_64/pgdg-redhat-repo-latest.noarch.rpm
```

AppStream同梱の`postgresql`モジュールがPGDGパッケージと衝突するため、OSのバージョンに応じて次のどちらかを実行してください。

**AlmaLinux / Rocky Linux 8・9 の場合**（モジュールを無効化する）:
```bash
sudo dnf -qy module disable postgresql
```

**AlmaLinux / Rocky Linux 10 の場合**（モジュール機構自体が廃止されているため、この手順は不要。何も実行しなくてよい）:
```bash
# 実行不要（上記コマンドは10には存在しないモジュールを指しており失敗します）
```

続き（共通）:
```bash
# OpenLiteSpeed 公式リポジトリ
sudo bash -c 'curl -s https://repo.litespeed.sh | bash'

# Node.js は 24 LTS（22は保守入り / 20はEOL）。ビルド専用途。NodeSource推奨。
curl -fsSL https://rpm.nodesource.com/setup_24.x | sudo bash -
# （AppStream を使う場合）: sudo dnf -y module enable nodejs:24  ※無ければ NodeSource を使う
```

---

## 3. PostgreSQL 16

```bash
sudo dnf -y install postgresql16-server postgresql16
sudo /usr/pgsql-16/bin/postgresql-16-setup initdb
sudo systemctl enable --now postgresql-16

# DB / ユーザー作成（Docker版と同じ名前）
# 'loghub' はユーザー名と同じ値のサンプルなので、本番では強力なパスワードに変更すること
sudo -u postgres psql <<'SQL'
CREATE USER loghub WITH PASSWORD 'loghub';
CREATE DATABASE loghub OWNER loghub;
GRANT ALL PRIVILEGES ON DATABASE loghub TO loghub;
SQL
```

> **本番では強力なパスワードに変更すること**。上記の `'loghub'` はユーザー名と同じ弱いサンプル値。
> 例: `openssl rand -base64 24` で生成した値に置き換え、後述の `.env` の `DATABASE_URL` にも同じ値を反映する。

`/var/lib/pgsql/16/data/pg_hba.conf` でローカル接続を許可（password/scram）。例:
```
host    loghub    loghub    127.0.0.1/32    scram-sha-256
```
変更後 `sudo systemctl restart postgresql-16`。

---

## 4. backend（Python + FastAPI + Uvicorn）

```bash
# コード取得（このリポジトリ）
sudo mkdir -p /opt/loghub && sudo chown "$USER" /opt/loghub
git clone <YOUR_REPO_URL> /opt/loghub
cd /opt/loghub/backend

# Python 3.12 + venv
sudo dnf -y install python3.12 python3.12-pip
python3.12 -m venv /opt/loghub/venv
/opt/loghub/venv/bin/pip install --upgrade pip
/opt/loghub/venv/bin/pip install -r requirements.txt
```

環境変数ファイル `/opt/loghub/backend/.env`（systemd から読ませる）:
```ini
DATABASE_URL=postgresql+psycopg://loghub:loghub@127.0.0.1:5432/loghub
INGEST_TOKEN=
TCP_INGEST_PORT=516
GEOIP_DB_PATH=/opt/loghub/backend/geoip/GeoLite2-Country.mmdb
JSON_STORE_DIR=/opt/loghub/data/json
LICENSE_SECRET=
```

> **`INGEST_TOKEN` は空欄のままにしないこと**。外部からログを受け取り得るVPS運用では、
> 空欄＝認証なしで `/ingest` を晒すことになり危険。必ずランダムな値を生成して設定する。
> 生成例: `openssl rand -hex 32`
>
> **`LICENSE_SECRET` も空欄のままにしないこと**。空欄だと開発用の弱い既定値にフォールバックし、
> 既定値のままだと誰でもライセンスキーを偽造できてしまう（[docs/licensing.md](licensing.md) 参照）。
> 生成例: `openssl rand -base64 32`

systemd ユニット `/etc/systemd/system/loghub-backend.service`:
```ini
[Unit]
Description=loghub backend (FastAPI/Uvicorn + TCP ingest)
After=network.target postgresql-16.service
Wants=postgresql-16.service

[Service]
WorkingDirectory=/opt/loghub/backend
EnvironmentFile=/opt/loghub/backend/.env
# TCP受信スレッドはプロセス内で1回だけbindするため、ワーカーは1（uvicorn単一プロセス）
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
```

> **スケール時の注意**: 複数ワーカー（gunicorn 等）にすると TCP 516 の bind が競合する。
> ワーカーを増やすなら、TCP受信だけ別 systemd サービスに分離する
> （`ExecStart=/opt/loghub/venv/bin/python -c "from app.tcp_ingest import _serve; _serve(516)"`）。

初回の取り込み（テスト用、任意）:
```bash
cd /opt/loghub/backend
/opt/loghub/venv/bin/python -m app.tools.load_logs --reset
```

---

## 5. frontend（Node でビルド → 静的ファイル）

本番は dev サーバではなくビルド済み静的ファイルを LiteSpeed が配信する。
LiteSpeed が `/api` を中継するので **`VITE_API_BASE` は空**（同一オリジン）でビルドする。

```bash
sudo dnf -y install nodejs
cd /opt/loghub/frontend
npm install
VITE_API_BASE="" npm run build      # 生成: /opt/loghub/frontend/dist
```

配信用に配置（例）:
```bash
sudo mkdir -p /var/www/loghub
sudo cp -r dist/* /var/www/loghub/
```

---

## 6. OpenLiteSpeed（配信 + リバースプロキシ）

```bash
sudo dnf -y install openlitespeed
sudo systemctl enable --now lsws
# 管理画面パスワード設定（管理は :7080）
sudo /usr/local/lsws/admin/misc/admpass.sh
```

WebAdmin（`https://<host>:7080`）で以下を設定（または設定ファイル直接編集）:

1. **External App（プロキシ先）**: Type=Web Server、Address=`127.0.0.1:8000`、名前 `loghub-backend`。
2. **Virtual Host** `loghub`:
   - Document Root: `/var/www/loghub`
   - **Context `/` (Static)**: 静的配信。`index.html`。SPAなので 404 を `/index.html` に rewrite（任意）。
   - **Context `/api` (Proxy)** → External App `loghub-backend`
   - **Context `/ingest` (Proxy)** → `loghub-backend`
   - **Context `/health` (Proxy)** → `loghub-backend`
3. **Listener** `:80`（必要なら `:443` を Let's Encrypt 証明書付きで）→ 上記 VHost にマップ。

> 設定ファイルで書く場合は `/usr/local/lsws/conf/vhosts/loghub/vhconf.conf` に
> `context /api/ { type proxy; handler loghub-backend; }` のように記述（`/ingest/` `/health` も同様）。

### 443（TLS）を有効化する場合: Let's Encrypt（certbot）で証明書取得

```bash
sudo dnf -y install certbot

# OpenLiteSpeed を一時停止し standalone モードで取得（80番を使うため）
sudo systemctl stop lsws
sudo certbot certonly --standalone -d <your-domain>
sudo systemctl start lsws

# 証明書の出力先（例）:
#   /etc/letsencrypt/live/<your-domain>/fullchain.pem
#   /etc/letsencrypt/live/<your-domain>/privkey.pem
```

WebAdmin の Listener `:443` に上記2ファイルを設定（証明書ファイル / 秘密鍵ファイル）。
自動更新の確認・設定（更新時に LiteSpeed を再起動するフックを追加）:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/lsws-restart.sh >/dev/null <<'EOF'
#!/bin/sh
systemctl restart lsws
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/lsws-restart.sh

# certbot タイマーは dnf install 時に自動で有効化される。確認:
sudo systemctl status certbot-renew.timer
# 更新のドライラン
sudo certbot renew --dry-run
```

これで `http://<host>/` で画面、`/api/...` `/ingest` がバックエンドへ中継される
（Docker版の Vite proxy と同じ役割を LiteSpeed が担う）。

---

## 7. pgAdmin 4（server mode）

LiteSpeed のみを Web サーバにするため、pgAdmin は Gunicorn で動かし `/pgadmin` をプロキシする。

```bash
python3.12 -m venv /opt/pgadmin/venv
/opt/pgadmin/venv/bin/pip install --upgrade pip
/opt/pgadmin/venv/bin/pip install pgadmin4 gunicorn

sudo mkdir -p /var/lib/pgadmin /var/log/pgadmin
sudo chown -R loghub:loghub /var/lib/pgadmin /var/log/pgadmin
```

`config_local.py`（pgadmin パッケージ内 `pgadmin4/` に作成）:
```python
import os
DATA_DIR = '/var/lib/pgadmin'
LOG_FILE = '/var/log/pgadmin/pgadmin4.log'
SERVER_MODE = True
```

初回管理ユーザー作成 → Gunicorn を systemd 化（`127.0.0.1:5050`）→ LiteSpeed で **Context `/pgadmin` (Proxy)** を `127.0.0.1:5050` に向ける。
pgAdmin の接続先 DB は Host=`127.0.0.1` Port=`5432` User=`loghub` DB=`loghub`。

> 簡易にするなら pgAdmin 公式RPM（`dnf install pgadmin4-web` → `/usr/pgadmin4/bin/setup-web.sh`）も可。
> ただしそれは httpd を導入するため、LiteSpeed と 80番が競合しないよう注意（別ポート/別ホストにする）。

---

## 8. firewalld / SELinux

```bash
# 公開: 80/443、TCP NDJSON 受信(516)は外部送信元がある場合のみ
sudo firewall-cmd --permanent --add-service=http --add-service=https
sudo firewall-cmd --permanent --add-port=516/tcp
sudo firewall-cmd --reload
# 8000 と 5432 は開けない（localhost専用）
```

> **516 を開けるかどうかの判断基準**:
> - NXLog などの送信元がこの VPS **自身（127.0.0.1）から POST するだけ**の構成であれば、
>   516 は外部公開する必要が無い。`--add-port=516/tcp` は実行せず、閉じたままにする。
> - VPS の外にある送信元（社内NW/他ホストの NXLog 等）から直接 TCP で送る構成の場合のみ、
>   516 を開放し、可能であれば `--add-rich-rule` などで送信元IPを限定する。

SELinux（Enforcing 前提）:
- LiteSpeed から `127.0.0.1:8000` / `:5050` へプロキシ接続を許可:
  `sudo setsebool -P httpd_can_network_connect 1`（LSWSにも適用される）
- pgAdmin/loghub のデータディレクトリのコンテキストに注意（`/var/lib/pgadmin`, `/opt/loghub/data`）。
  問題が出たら `ausearch -m AVC -ts recent` で確認し、必要に応じて `semanage fcontext` / `restorecon`。

---

## 9. 起動順序・確認

```bash
sudo systemctl enable --now postgresql-16 loghub-backend lsws
# pgadmin の gunicorn サービスも enable --now

curl -s http://127.0.0.1:8000/health           # backend 単体
curl -s "http://<host>/api/dashboard/summary"   # LiteSpeed 経由でAPI
# 画面: http://<host>/      pgAdmin: http://<host>/pgadmin
```

ログ取り込みの確認（REST / TCP）:
```bash
# REST
curl -X POST "http://<host>/ingest?source=web01&source_type=web_access" \
  -H 'Content-Type: application/json' \
  -d '{"vhost":"example.com","client":"203.0.113.5","time":"2026-06-26T19:00:00+09:00","request":"GET / HTTP/1.1","status":"200"}'
# TCP NDJSON
printf '%s\n' '{"source":"web01","source_type":"web_access","vhost":"example.com","client":"203.0.113.5","request":"GET / HTTP/1.1","status":"200"}' | nc <host> 516
```

---

## 10. 補足

- **入力は JSON のみ**（REST `/ingest` ＋ TCP NDJSON `516`）。送信側（NXLog 等）が JSON 化して送る前提。画面からのファイルアップロードは無し。
- 運用更新: コード更新 → backend は `pip install -r requirements.txt` 後 `systemctl restart loghub-backend`、frontend は `npm run build` し直して `dist` を再配置。
- バックアップ対象: PostgreSQL（`pg_dump`）、`/opt/loghub/data`（取り込みJSON）、各 `.env` / LiteSpeed 設定。
- セキュリティ: 外部公開時は `INGEST_TOKEN` を必須化し、516 はファイアウォールで送信元IPを限定。443 を有効化して HTTP は 443 へリダイレクト。

### pg_dump の定期自動実行

バックアップ先ディレクトリとスクリプトを用意:
```bash
sudo mkdir -p /var/backups/loghub
sudo tee /usr/local/bin/loghub-pg-backup.sh >/dev/null <<'EOF'
#!/bin/sh
set -eu
DEST=/var/backups/loghub
STAMP=$(date +%Y%m%d-%H%M%S)
sudo -u postgres pg_dump -Fc loghub > "$DEST/loghub-$STAMP.dump"
# 7日より古い世代を削除
find "$DEST" -name 'loghub-*.dump' -mtime +7 -delete
EOF
sudo chmod +x /usr/local/bin/loghub-pg-backup.sh
```

**方法A: systemd timer（推奨）**
```ini
# /etc/systemd/system/loghub-pg-backup.service
[Unit]
Description=loghub PostgreSQL backup (pg_dump)

[Service]
Type=oneshot
ExecStart=/usr/local/bin/loghub-pg-backup.sh
```
```ini
# /etc/systemd/system/loghub-pg-backup.timer
[Unit]
Description=Run loghub-pg-backup daily

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
```
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now loghub-pg-backup.timer
systemctl list-timers loghub-pg-backup.timer   # 次回実行時刻の確認
```

**方法B: cron**
```bash
# root の crontab に追記（毎日3:00に実行）
echo '0 3 * * * /usr/local/bin/loghub-pg-backup.sh' | sudo tee -a /etc/crontab
```
