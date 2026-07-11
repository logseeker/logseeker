# セキュリティ運用ガイド（LogSeeker）

デモ/ローカルでは利便性優先で認証なしで動くが、**VPS等で公開する前に必ず以下を実施**すること。

## 1. 管理画面(/api・フロント)に認証をかける ★最重要
現状 `/api/*` と画面には認証がない（`/ingest` のみ `INGEST_TOKEN` で保護）。
アプリ自体のログイン必須化（`AUTH_REQUIRED=true`、[docs/auth.md](auth.md)）に加え、
リバースプロキシで Basic 認証を重ねがけするのも有効。

```sh
sudo dnf -y install httpd-tools   # htpasswdコマンド（Debian/Ubuntu系なら apache2-utils）
```

nginx（[INSTALL.md](../INSTALL.md)使用時）の場合:
```sh
htpasswd -nbB admin 'ここに強いパスワード' | sudo tee /etc/nginx/.htpasswd
# nginx の該当locationに auth_basic / auth_basic_user_file を追加 → 再読み込み
sudo nginx -t && sudo systemctl reload nginx
```

Apache（[INSTALL-pgadmin.md](../INSTALL-pgadmin.md)使用時）の場合:
```sh
htpasswd -cB /etc/httpd/.htpasswd admin   # 対話式でパスワード入力
# 該当 <Directory>/<Location> に AuthType Basic / AuthUserFile / Require valid-user を追加 → 再読み込み
sudo apachectl configtest && sudo systemctl reload httpd
```

`/ingest` は機器からの送信経路なので Basic 認証の対象外にしてあり、`INGEST_TOKEN` で保護する。

## 2. /ingest にトークンを設定
`.env` の `INGEST_TOKEN` に長いランダム文字列を設定（生成例: `openssl rand -hex 32`）。
送信側は `Authorization: Bearer <token>` を付与。詳細は [INSTALL.md](../INSTALL.md) §7 参照。

## 3. 直接ポートを閉じる
本番では nginx(80/443)（またはApache。[INSTALL-pgadmin.md](../INSTALL-pgadmin.md)使用時）だけを
公開する（[INSTALL.md](../INSTALL.md) §6のfirewalld設定）:
- backend(8000)・PostgreSQL(5432) は `127.0.0.1` バインドのみ。firewalldで開放しない
- 公開するのは 80/443 と、必要なら `TCP_INGEST_PORT`(516) のみ
- 516番ポートを開放するかどうかの判断基準は [INSTALL.md](../INSTALL.md) §6 参照

## 4. HTTPS 化
公開時は 443/TLS。証明書は Let's Encrypt 等。nginx に `listen 443 ssl;` を追加。

## 5. 秘密情報の扱い
- `LICENSE_SECRET` は**必ず**長いランダム値へ変更（既定値のままだと誰でもライセンスキーを偽造可能。
  生成例: `openssl rand -base64 32`）。詳細は [INSTALL.md](../INSTALL.md) §7 参照。
- PostgreSQL の DB パスワード（既定値 `logseeker`）も秘密情報として扱い、本番では強力な値に変更する。
  詳細は [INSTALL.md](../INSTALL.md) §2 参照。
- SMTP パスワード / IOC APIキー は DB に平文保存される（送信・同期に必要なため）。
  - API 応答では SMTP パスワードは `***` でマスク、IOC キーは返さない（有無のみ）。
  - DB(pgdata) と DBバックアップの保護（アクセス制限・暗号化ディスク）を行う。
- Slack Webhook URL は秘密情報。設定画面にアクセスできる人＝送信先を変更できる人なので、認証(項番1)は必須。

## 6. 既知の入力対策（実装済み）
- 受信JSONは**無改変で保存**、正規化は派生層。SQLは全て**バインドパラメータ**（SQLインジェクション対策済み）。
- `/ingest` は `MAX_INGEST_BYTES`、TCP受信は `TCP_MAX_LINE_BYTES` でサイズ制限（メモリ枯渇/DoS対策）。
- 不正JSONは dead_letter に隔離し、他レコードの取り込みは継続。
- CORS は既定 `*`（Viteプロキシで同一オリジンのため実質不要）。公開時は `CORS_ORIGINS` を自分のオリジンに絞る。

## 7. ライセンス既定
- Tierによるログ種別の制限、及びAPIオプションの制限は撤廃済み（[LICENSE](../LICENSE) 第5条）。全ログ種別・APIオプションは既定で無償利用可能。
- ライセンスキーが制御するのは**データ保持期間の延長**（既定90日）のみ。詳細は [docs/licensing.md](licensing.md) / [docs/retention.md](retention.md) 参照。
