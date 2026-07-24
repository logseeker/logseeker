# セキュリティ運用ガイド（LogSeeker）

デモ/ローカルでは利便性優先で認証なしで動くが、**VPS等で公開する前に必ず以下を実施**すること。

## 1. 管理画面(/api・フロント)に認証をかける ★最重要
現状 `/api/*` と画面には認証がない（`/ingest` のみ `INGEST_TOKEN` で保護）。
nginx で Basic 認証をかけるのが最短。

```sh
# htpasswd 生成（admin ユーザー）
docker run --rm httpd:alpine htpasswd -nbB admin 'ここに強いパスワード' > nginx/.htpasswd
# nginx/default.conf の auth_basic 2行のコメントを外す → 再起動
docker compose restart nginx
```
`/ingest` は機器からの送信経路なので Basic 認証の対象外にしてあり、`INGEST_TOKEN` で保護する。

## 2. /ingest にトークンを設定
`.env` の `INGEST_TOKEN` に長いランダム文字列を設定。送信側は `Authorization: Bearer <token>` を付与。
生成手順は deploy手順書（`docs/deploy-vps-almalinux-lsws.md` §4）参照。

## 3. 直接ポートを閉じる
本番では nginx(80/443) だけを公開し、以下の**直接ポート公開を削除**する（docker-compose.yml の `ports:`）:
- `backend` 8000 / `db` 5432 / `pgadmin` 5050 → いずれもホスト公開不要（コンテナ間通信のみで動く）
- 残すのは `nginx` の 80（443）と、必要なら `TCP_INGEST_PORT`(516) のみ
- 516番ポートを開放するかどうかの判断基準は `docs/deploy-vps-almalinux-lsws.md` §8 参照

## 4. HTTPS 化
公開時は 443/TLS。証明書は Let's Encrypt 等。nginx に `listen 443 ssl;` を追加。

## 5. 秘密情報の扱い
- `LICENSE_SECRET` は**必ず**長いランダム値へ変更（既定値のままだと誰でもライセンスキーを偽造可能）。
  生成手順は deploy手順書（`docs/deploy-vps-almalinux-lsws.md` §4）参照。
- PostgreSQL の DB パスワード（既定値 `logseeker`）も秘密情報として扱い、本番では強力な値に変更する。
  詳細は deploy手順書（`docs/deploy-vps-almalinux-lsws.md` §3）参照。
- SMTP パスワード / IOC APIキー は DB に平文保存される（送信・同期に必要なため）。
  - API 応答では SMTP パスワードは `***` でマスク、IOC キーは返さない（有無のみ）。
  - DB(pgdata) と DBバックアップの保護（アクセス制限・暗号化ディスク）を行う。
- Slack Webhook URL は秘密情報。設定画面にアクセスできる人＝送信先を変更できる人なので、認証(項番1)は必須。

## 6. 既知の入力対策（実装済み）
- 受信JSONは**無改変で保存**、正規化は派生層。SQLは全て**バインドパラメータ**（SQLインジェクション対策済み）。
- `/ingest` は `MAX_INGEST_BYTES`、TCP受信は `TCP_MAX_LINE_BYTES` でサイズ制限（メモリ枯渇/DoS対策）。
- 不正JSONは dead_letter に隔離し、他レコードの取り込みは継続。
- CORS は既定 `*`（Viteプロキシで同一オリジンのため実質不要）。公開時は `CORS_ORIGINS` を自分のオリジンに絞る。

## 7. 管理パネルへのIPアクセス制限（アプリ層・任意）
`?screen=administration`（左メニューには出さない、管理者(admin)ロール専用の別ログイン画面。
[docs/auth.md](auth.md)「管理パネル」参照）そのものへのアクセスを、許可したIP/CIDR以外は
拒否できる。SSHの送信元IP制限やWordPress管理画面のIP制限などと同じ発想＝「そもそもログイン
試行自体をそのIP以外弾く」もの。既定はOFF＝無効。通常のログイン後画面（ユーザー管理・監査ログ・
ライセンス・通知設定・脅威インテリ等）はこの対象外で、今まで通りロール(sysadmin以上)だけで守る。

- **nginx/Apache/OpenLiteSpeed のどれでも追加設定なしで機能する**：判定にはリバースプロキシが
  `X-Forwarded-For` に追記した「末尾」の値を使う（`backend/app/auth.py` の `access_control_ip()`）。
  これは各ミドルウェアがリバースプロキシとして動く際の標準動作（nginxは
  `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`、Apache(mod_proxy_http)は既定の
  `ProxyAddHeaders On`、OpenLiteSpeedも同様）のため、クライアントが自分で偽の`X-Forwarded-For`を
  送りつけても先頭に追加されるだけで末尾（＝プロキシ自身が観測した値）は書き換えられない。
  監査ログ表示用の送信元IP（`client_ip()`、先頭を採用）とは判定方法が異なるので混同しないこと。
- **ロックアウト防止**：有効化する際、今アクセスしているIPが許可リストに含まれていないと
  保存自体を拒否する。管理パネルには「現在検出しているあなたのIP」が常に表示されるので、
  それを見てから許可リストに追加する。
- **万一ロックアウトした場合**：DBの`settings`テーブルから`ip_restrict_enabled`行を削除（または
  値を`false`に更新）すれば即座に無効化できる（`psql`やpgAdminから直接操作。アプリの再起動は不要）。
- あくまでアプリ層での防御であり、ミドルウェア/ファイアウォールでの遮断より弱い
  （拒否されたリクエストも一度はアプリまで到達する）。より強固にしたい場合は、
  Apacheなら`<Location>`+`Require ip`、nginxなら`allow`/`deny`、firewalldのrich-ruleなど
  ネットワーク層での制限と併用するとよい。

## 8. ライセンス既定
- Tierによるログ種別の制限、及びAPIオプションの制限は撤廃済み。全ログ種別・APIオプションは既定で無償利用可能。
- ライセンスキーが制御するのは**データ保持期間の延長**（既定90日）のみ。詳細は [docs/licensing.md](licensing.md) / [docs/retention.md](retention.md) 参照。
