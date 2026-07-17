# INSTALL.md — オンプレ・ネイティブインストール手順（Docker不使用・pgAdminなし）

このリポジトリは Docker を同梱していません。PostgreSQL / Python(FastAPI) / Node.js(ビルドのみ) を
直接インストールし、`systemd` でbackendを常駐、`nginx`（または Caddy）でTLS終端とリバースプロキシを行う構成です。

> **対象OS**: RHEL系（AlmaLinux 8/9/10, RHEL, Rocky Linux）を主対象にしています。
> パッケージ管理は `dnf`、ファイアウォールは `firewalld` を前提にしたコマンド例です。
> Debian/Ubuntu系の場合は `apt` / `ufw` に読み替えてください（パッケージ名はおおむね同じか近い名前です）。
>
> **pgAdmin（DB管理画面）を使いたい場合はこの手順ではなく [INSTALL-pgadmin.md](INSTALL-pgadmin.md) を使ってください。**
> pgAdminの公式パッケージはApacheを前提にしているため、nginxと二重にWebサーバーを持たないよう
> pgAdminを使う場合はApache一本化の別手順に分けています。詳細は [INSTALL-pgadmin.md](INSTALL-pgadmin.md) 冒頭を参照。

---

## 目次

- [0. 構成概要](#0-構成概要)
- [1. 必要ソフトウェア](#1-必要ソフトウェア)
- [2. PostgreSQL のインストールと初期化](#2-postgresql-のインストールと初期化)
- [3. backend（Python + FastAPI）の venv セットアップ](#3-backendpython--fastapiの-venv-セットアップ)
- [4. frontend のビルドと静的ファイルの配置](#4-frontend-のビルドと静的ファイルの配置)
- [5. nginx でのリバースプロキシ設定（443でTLS終端）](#5-nginx-でのリバースプロキシ設定443でtls終端)
- [6. TCP ingest リスナー用のポート開放（firewalld）](#6-tcp-ingest-リスナー用のポート開放firewalld)
  - [6.1 複数NIC・プライベートスイッチ環境でeth1のみに絞る場合](#61-複数nicプライベートスイッチ環境でeth1ローカル側のみに絞る場合)
- [7. `.env` の設定箇所と主要な環境変数](#7-env-の設定箇所と主要な環境変数)
- [8. 起動順序・動作確認](#8-起動順序動作確認)
- [9. 補足](#9-補足)

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
```

AppStream同梱の`postgresql`モジュールがPGDGパッケージと衝突するため、OSのバージョンに応じて次のどちらかを実行してください。

**AlmaLinux / RHEL / Rocky Linux 8・9 の場合**（モジュールを無効化する）:
```bash
sudo dnf -qy module disable postgresql
```

**AlmaLinux / RHEL / Rocky Linux 10 の場合**（モジュール機構自体が廃止されているため、この手順は不要。何も実行しなくてよい）:
```bash
# 実行不要（上記コマンドは10には存在しないモジュールを指しており失敗します）
```

続き（共通）:
```bash
# Node.js 24 LTS（ビルド専用途。NodeSource推奨）
curl -fsSL https://rpm.nodesource.com/setup_24.x | sudo bash -
sudo dnf -y install nodejs

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
CREATE USER logseeker WITH PASSWORD 'ここを強いパスワードに変更';
CREATE DATABASE logseeker OWNER logseeker;
SQL
```

`/var/lib/pgsql/16/data/pg_hba.conf` にローカル接続の許可を追加（例）。各列の意味（1列目の`host`は
接続方式を表す固定キーワード。書き換えるのは2列目=データベース名・3列目=ユーザー名）:
```
# host    <データベース名>    <ユーザー名>    <許可するアドレス/CIDR>    <認証方式>
host    logseeker    logseeker    127.0.0.1/32       scram-sha-256
# 任意: backendを別ホスト（同一LAN内）で動かす場合のみ追加。CIDRは自環境のLANセグメントに置き換える
host    logseeker    logseeker    192.168.1.0/24     scram-sha-256
```

LAN内の別ホストから接続を許可する場合は、`postgresql.conf` の `listen_addresses` も
`listen_addresses = '*'`（または自ホストのLAN側IPを明示）に変更し、firewalldで5432を
そのLANセグメントに限定して開放する必要があります（例: `sudo firewall-cmd --permanent --zone=internal --add-port=5432/tcp`。
`--zone`はLAN側インターフェースが所属するゾーンに合わせる）。§0の方針どおり、backendと同一ホストで完結する
構成であればこの追加設定は不要です。

変更後: `sudo systemctl restart postgresql-16`

テーブルはbackend初回起動時に自動作成されます（マイグレーション不要、`Base.metadata.create_all`）。

<details>
<summary>誤って <code>loghub</code> の名前で作ってしまった場合の削除手順</summary>

> **誤って `loghub` という名前でDB/ユーザーを作成してしまった場合**（旧版の手順や本書以外の資料に従った等）、
> 削除してから上記のコマンドで `logseeker` として作り直してください。
> ```bash
> sudo -u postgres psql <<'SQL'
> DROP DATABASE IF EXISTS loghub;
> DROP USER IF EXISTS loghub;
> SQL
> ```
> `/opt/loghub` や systemd サービスも同様に作ってしまっている場合は、§3末尾の削除コマンドも参照してください。

</details>

---

## 3. backend（Python + FastAPI）の venv セットアップ

```bash
# コード配置
sudo mkdir -p /opt/logseeker && sudo chown "$USER" /opt/logseeker
git clone <YOUR_REPO_URL> /opt/logseeker
# もしくは、このtarball/zipを /opt/logseeker に展開

cd /opt/logseeker/backend
sudo dnf -y install python3.12 python3.12-pip
python3.12 -m venv /opt/logseeker/venv
/opt/logseeker/venv/bin/pip install --upgrade pip
/opt/logseeker/venv/bin/pip install -r requirements.txt
```

### .env の設置

```bash
cp /opt/logseeker/.env.example /opt/logseeker/backend/.env
# 値を編集（DATABASE_URL・LICENSE_SECRET 等。主要な環境変数は §7 参照）
```

### systemd unit（`/etc/systemd/system/logseeker-backend.service`）

```ini
[Unit]
Description=LogSeeker backend (FastAPI/Uvicorn + TCP ingest)
After=network.target postgresql-16.service
Wants=postgresql-16.service

[Service]
WorkingDirectory=/opt/logseeker/backend
EnvironmentFile=/opt/logseeker/backend/.env
# TCP受信スレッドはプロセス内で1回だけbindするため、ワーカーは1（uvicorn単一プロセス）にする
ExecStart=/opt/logseeker/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=always
User=logseeker
Group=logseeker
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

> `TCP_INGEST_PORT`の既定値516は1024未満の特権ポートのため、`User=logseeker`（非root）のままでは
> 本来bindできません。`AmbientCapabilities=CAP_NET_BIND_SERVICE`により、rootに昇格せずこの
> プロセスにだけ「1024未満のポートにbindする」権限を個別に付与しています（`CapabilityBoundingSet`
> で保持できる権限をこの1つだけに絞り込み、他の特権は一切持てないようにしています）。

```bash
sudo useradd -r -s /sbin/nologin logseeker 2>/dev/null || true
sudo chown -R logseeker:logseeker /opt/logseeker
sudo systemctl daemon-reload
sudo systemctl enable --now logseeker-backend
sudo systemctl status logseeker-backend
```

<details>
<summary>複数ワーカー構成にする場合の注意（該当者のみ）</summary>

> **スケール時の注意**: 複数ワーカー（gunicorn等）にすると TCP ingestポートのbindが競合します。
> ワーカーを増やす場合は、TCP受信だけを別systemdサービスに分離してください
> （`ExecStart=/opt/logseeker/venv/bin/python -c "from app.tcp_ingest import _serve; _serve(516)"`）。

</details>

<details>
<summary>誤って <code>loghub</code> の名前で作ってしまった場合の削除手順</summary>

> **誤って `loghub` の名前でセットアップしてしまった場合**の削除コマンド（`/opt/logseeker` 等
> `logseeker` の名前で作り直す前に実行）:
> ```bash
> sudo systemctl disable --now loghub-backend 2>/dev/null || true
> sudo rm -f /etc/systemd/system/loghub-backend.service
> sudo systemctl daemon-reload
> sudo userdel loghub 2>/dev/null || true
> sudo rm -rf /opt/loghub
> sudo rm -rf /var/www/loghub
> sudo rm -f /etc/nginx/conf.d/loghub.conf   # nginx使用時
> ```

</details>

---

## 4. frontend のビルドと静的ファイルの配置

本番は開発サーバ（`npm run dev`）ではなく、ビルド済み静的ファイルをnginxが配信します。
nginxが `/api` `/ingest` を中継するので **`VITE_API_BASE` は空**（同一オリジン）でビルドします。

```bash
cd /opt/logseeker/frontend
npm ci      # package-lock.json通りに再現性のあるインストール（package.jsonとの不整合は即エラーになる）
VITE_API_BASE="" npm run build      # 生成: /opt/logseeker/frontend/dist

sudo mkdir -p /var/www/logseeker
sudo cp -r dist/* /var/www/logseeker/
sudo chown -R nginx:nginx /var/www/logseeker   # SELinux Enforcing環境の権限に合わせる
```

コード更新時は `npm run build` をやり直して `/var/www/logseeker` へ再配置してください。

---

## 5. nginx でのリバースプロキシ設定（443でTLS終端）

`/etc/nginx/conf.d/logseeker.conf`:

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
    # nginx 1.25.1以降は「listen ... http2;」が非推奨（別途 http2 on; を使う新構文）。
    # 1.25.1未満では逆に新構文はエラーになるため、使用中のnginxバージョンに応じて読み替えること。
    listen 443 ssl http2;
    server_name your-domain.example.com;

    ssl_certificate     /etc/letsencrypt/live/your-domain.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.example.com/privkey.pem;

    # backend側のMAX_INGEST_BYTES(既定5MB)に合わせる。ヘッダ等のオーバーヘッド分の余裕を見て8MBに設定
    client_max_body_size 8m;

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
    root /var/www/logseeker;
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
        root * /var/www/logseeker
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

> **516を開けるかどうかの判断基準**:
> - NXLog等の送信元がこのサーバー**自身（127.0.0.1）からPOSTするだけ**の構成であれば、516は
>   外部公開する必要が無い。`--add-port=516/tcp` は実行せず、閉じたままにする。
> - サーバーの外にある送信元（社内NW/他ホストのNXLog等）から直接TCPで送る構成の場合のみ、
>   516を開放し、可能であれば`--add-rich-rule`等で送信元IPを限定する（§6.1も参照）。

```bash
# firewalldはイメージによっては未起動なので、まず確実に起動しておく
sudo systemctl enable --now firewalld

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

### 6.1 複数NIC・プライベートスイッチ環境でeth1（ローカル側）のみに絞る場合

<details>
<summary>複数NIC・プライベートスイッチ環境向けの設定（該当者のみ）</summary>

さくらのVPS「スイッチ」など、L2の専用線でサーバー間を直結できるプロバイダの機能を使う場合の手順です
（例: `eth0`=グローバルIP、`eth1`=スイッチ経由のローカルIP。両ホストがスイッチに接続済みで、
ping疎通は既に取れている前提）。

TCP ingestやbackendのAPIはアプリ側で `0.0.0.0` にbindされていて構いません。制御はfirewalldで
**eth0とeth1を別ゾーンに分け、開放するポートをeth1側のゾーンにしか追加しない**ことで行います。
これによりeth0（インターネット側）からは到達不能、eth1（スイッチ経由）からのみ到達可能になります。

受信サーバー側:
```bash
# 現在のインターフェース→ゾーン割り当てを確認
sudo firewall-cmd --get-active-zones
nmcli con show

# eth1を専用ゾーン（例: internal）に割り当てる（eth0はpublicのまま変更しない）
sudo firewall-cmd --permanent --zone=internal --change-interface=eth1

# TCP ingestポート(516)は internal ゾーンにのみ開放する（publicゾーンには追加しない）
sudo firewall-cmd --permanent --zone=internal --add-port=516/tcp

# さらに厳格にする場合、送信元をスイッチのCIDRに絞る
sudo firewall-cmd --permanent --zone=internal --add-source=<スイッチのローカルCIDR>/24

sudo firewall-cmd --reload
```

`<スイッチのローカルCIDR>` は `ip -4 addr show eth1` で確認できる、スイッチ作成時に自分で決めたセグメントです。

送信サーバー側は、ログ転送設定（NXLog等）の宛先を**受信サーバーのeth1側IP**（グローバルIPではなく）
に向けます。スイッチ内は同一L2セグメントなのでゲートウェイ指定は不要です。

```
# 例: NXLogやsyslog転送設定の宛先
192.168.100.20:516   # ← 受信サーバーのeth1側IP
```

注意点:
- eth1側に**デフォルトゲートウェイを設定しない**でください（両NICにデフォルトルートがあると経路が
  不安定になるため、デフォルトゲートウェイはeth0側だけに残す）。
- §2で作成した `pg_hba.conf` のLAN向けCIDR例（`192.168.1.0/24`）を使う場合は、実際のスイッチCIDRに
  置き換えてください。backendとPostgreSQLを同一サーバーに置く構成（本書の既定）ならこの設定自体不要です。

</details>

---

## 7. `.env` の設定箇所と主要な環境変数

`.env.example` をコピーして `/opt/logseeker/backend/.env` に配置し、値を編集します（§3参照）。
systemd unitの `EnvironmentFile=` がこのファイルを読み込みます。

| 変数 | 説明 | 既定値 |
|---|---|---|
| `DATABASE_URL` | PostgreSQL接続文字列 | `postgresql+psycopg://logseeker:logseeker@localhost:5432/logseeker` |
| `INGEST_TOKEN` | `/ingest` のBearer認証トークン。空なら認証なし。**外部公開時は必ず設定**（生成例: `openssl rand -hex 32`） | 空 |
| `TCP_INGEST_PORT` | TCP NDJSON受信ポート（0で無効） | `516` |
| `TCP_MAX_LINE_BYTES` | TCP受信1行あたりの最大バイト数（超過はdead_letterへ） | `1048576` |
| `MAX_INGEST_BYTES` | `/ingest` のリクエストサイズ上限 | `5242880` |
| `GEOIP_DB_PATH` | GeoLite2-Country.mmdb のパス（任意。[docs/geoip.md](docs/geoip.md)） | `backend/geoip/GeoLite2-Country.mmdb` |
| `JSON_STORE_DIR` | 取り込みJSON等の保存先の親ディレクトリ | `backend/data/json` |
| `CORS_ORIGINS` | CORS許可オリジン（カンマ区切り、`*`で全許可）。本番はフロントのオリジンに絞る | `*` |
| `LICENSE_SECRET` | ライセンスキー（データ保持期間の延長用）のHMAC署名鍵。**本番は必ず長いランダム文字列に変更**（既定値のままだと誰でもキーを偽造できる。生成例: `openssl rand -base64 32`） | 開発用の弱い既定値 |
| `LICENSE_KEY` | 初回デプロイ時に種まきする保持期間延長キー（任意。空ならWeb UIの「ライセンス」画面から適用） | 空 |
| `AUTH_REQUIRED` | ログイン必須化。外部公開するなら `true` 推奨（[docs/auth.md](docs/auth.md)） | `false` |
| `ROOT_USERNAME` / `ROOT_PASSWORD` | 初回起動時にのみ作成される管理者アカウント。**公開前に変更すること** | `logseeker` / `logseeker` |
| `SESSION_HOURS` | ログインセッションの有効時間 | `12` |

> ログ種別による機能制限、及びAPIオプションの制限は撤廃済み。すべて既定で無償利用可能（[docs/licensing.md](docs/licensing.md)）。
> ライセンスキーが制御するのはデータ保持期間の延長のみ（[docs/retention.md](docs/retention.md)）。

---

## 8. 起動順序・動作確認

```bash
sudo systemctl enable --now postgresql-16 logseeker-backend nginx   # (Caddy利用時は nginx の代わりに caddy)

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
- 運用更新: コード更新 → backendは `pip install -r requirements.txt` 後 `sudo systemctl restart logseeker-backend`、
  frontendは `npm run build` し直して `/var/www/logseeker` に再配置。
- バックアップ対象: PostgreSQL（`pg_dump`）、`JSON_STORE_DIR` 配下、`.env`、nginx/Caddy設定。
- 公開前に必ず [docs/security.md](docs/security.md) のチェックリストを確認してください
  （認証必須化・`INGEST_TOKEN`・`LICENSE_SECRET`変更・ポート閉塞・TLS等）。
- **pgAdmin（DB管理画面）が必要になった場合**、この手順のnginxはそのままに追加する方法は用意していません
  （nginxとpgAdmin付属のApacheが二重稼働するため）。[INSTALL-pgadmin.md](INSTALL-pgadmin.md) の
  Apache一本化手順に切り替えてください（PostgreSQL/backendのセットアップ内容は共通です）。
