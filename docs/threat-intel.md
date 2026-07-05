# 脅威インテリ（IOC）連携 — AbuseIPDB / AlienVault OTX

外部フィードを定期取得して**ローカルの脅威情報DB（`ioc` テーブル）**に保存し、取り込んだログの
IP/ドメインと**オフラインで突合**する。一致は「ルール / 注意喚起」とイベントの脅威=IOCに表示。

> 照合のたびに外部APIは叩かない（レート制限・遅延・オフライン不可を避けるため）。
> 「フィード同期 → ローカルDB → 高速突合」方式。

## 画面で設定（推奨）
左メニュー「**脅威インテリ**」：
- 各フィードに **APIキー入力**＋**自動同期の有効化**トグル → 保存
- **自動同期間隔**プルダウン（3 / 6 / 12 / 24 時間、既定6h）
- **今すぐ同期**ボタン（手動実行）
- 登録IOC件数・最終同期・状態を表示

## APIキーの取得方法
### AbuseIPDB
1. https://www.abuseipdb.com/ でアカウント作成
2. Account → **API** → API Key を発行（無料枠あり：blacklist取得に日次上限）
3. 画面「脅威インテリ」→ AbuseIPDB にキーを入力 → 有効化 → 保存
- 取得元：`GET https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90`（ヘッダ `Key`）

### AlienVault OTX
1. https://otx.alienvault.com/ でアカウント作成
2. Settings → **OTX Key**（無料）
3. 画面でキー入力 → 有効化 → 保存
- 取得元：`GET https://otx.alienvault.com/api/v1/pulses/subscribed`（ヘッダ `X-OTX-API-KEY`）。購読パルスの IP/ドメイン指標を取り込み
- ※ OTX は「購読(subscribe)したパルス」が対象。ダッシュボードで関心のあるパルスを購読しておく。

## REST API（自動化したい場合）
```bash
# 設定取得
curl http://<host>/api/ioc/feeds
# キー登録＋有効化（abuseipdb / otx）
curl -X POST http://<host>/api/ioc/feeds -H 'Content-Type: application/json' \
  -d '{"name":"abuseipdb","api_key":"YOUR_KEY","enabled":true}'
# 同期間隔（3/6/12/24）
curl -X POST http://<host>/api/ioc/settings -H 'Content-Type: application/json' -d '{"sync_hours":6}'
# 今すぐ同期
curl -X POST http://<host>/api/ioc/sync
```
> APIキーは応答に含めない（`has_key` の真偽のみ返す）。キーはDBに保存される（自己ホスト前提。DB/バックアップの取り扱いに注意）。

## 動作
- 自動同期スケジューラが起動時に動き、設定間隔ごとに有効フィードを取得 → `ioc` を **source 単位で全更新**（abuseipdb / otx）。
- 手元で登録した IOC（`data/ioc/` を `load_ioc` で取り込み）とも共存（source が異なる）。
- 突合結果は IP/ドメインのエンティティ × `ioc`。一致で「IOC一致 → ブロック推奨」。

## 将来
独自の脅威情報も同じ `ioc` テーブルへ追加可能（source を分ければ外部フィードと共存）。
内製IOC管理UI（追加/失効/タグ付け）を載せる拡張余地あり。
