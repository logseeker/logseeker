# PROJECT.md — API/TCP JSONイベント受信型 相関ログビューア

このドキュメントは、Claude Code への実装依頼仕様書である。

本システムは、JSONファイルアップロード型のログビューアではない。
API または TCP で受信した JSON イベントを保存し、検索・可視化・相関調査できるようにするためのログビューアである。

本システムは SIEM ではない。
ただし、将来的に SIEM 的な調査・分析・検知に発展できるよう、軽量タクソノミー、エンティティ抽出、相関表示、コメント、タグ、インシデント紐付けを前提に設計する。

---

## 0. 最重要方針

### 0.1 Docker構成は変更しない

既存の Docker 構成は変更しない。

維持するコンテナ構成:

```text
frontend
backend
db
pgadmin
```

役割:

```text
frontend : React + TypeScript + Vite + Tabler UI
backend  : Python + FastAPI
db       : PostgreSQL
pgadmin  : pgAdmin
```

コンテナ名、役割、基本構成は変えない。
ただし、各コンテナ内の実装構造、DBスキーマ、API、画面、コンポーネント構成は本仕様に合わせて変更してよい。

---

### 0.2 JSONファイルアップロード機能は作らない

本番機能として、ユーザーが画面から JSON ファイルをアップロードする機能は作らない。

ログ入力は以下の2つを基本とする。

```text
1. REST API による JSON イベント受信
2. TCP による JSON Lines / NDJSON 受信
```

現在テストで JSON ファイルを使っている場合でも、それは開発・検証用である。
本番画面には「JSONファイルアップロード」機能を出さない。

開発補助として、ローカル JSON を `/ingest` に送る CLI、スクリプト、curl サンプルは作ってよい。
ただし、それはユーザー向け画面機能ではない。

---

### 0.3 「原本ログファイル」は管理しない

本システムでは、ファイルとしての原本ログは管理しない。

ログは送信側で JSON 化され、backend は JSON イベントとして受信する。
したがって、本システムの保存対象は **受信した JSON payload** である。

用語は以下を使う。

```text
受信JSON
受信イベント
JSONイベント
event payload
payload
```

以下の用語は避ける。

```text
原本ログ
生ログファイル
raw log file
アップロードファイル
```

payload 内に `raw` や `message` が含まれている場合、それらは payload の一部として扱う。

---

### 0.4 `syslog` を分類として使わない

画面、分類、source_type、凡例、フィルター、メニュー、グラフに `syslog` を出してはならない。

理由:

* 本システムは JSON イベントを受け取る
* syslog は変換前のログ形式・由来にすぎない
* 利用者が調査で見たいのは「syslog」ではなく、どの機器・どのサービス・どのログ種別かである

NG例:

```text
source_type = syslog
Dashboard凡例 = syslog
Events分類 = syslog
```

OK例:

```text
source_type = router
source_type = nas
source_type = auth
source_type = web_access
source_type = web_error
source_type = google_workspace_audit
source_type = application
source_type = system
source_type = unknown
```

表示名:

```text
router                 -> ルーター
nas                    -> NAS
auth                   -> 認証ログ
web_access             -> Webアクセス
web_error              -> Webエラー
google_workspace_audit -> Google Workspace監査
application            -> アプリケーション
system                 -> システム
unknown                -> Unknown
```

---

### 0.5 機器名・ホスト名・ドメイン名はログにある値を優先する

機器名・ホスト名・ドメイン名は、payload に存在する値を優先して表示する。

ただし、ログに存在しない値を parser が勝手に推定してはいけない。
たとえば、payload に `RTX1210` が無い場合、勝手に `RTX1210` と表示してはいけない。

表示優先順位:

```text
1. payload.device_name
2. payload.hostname
3. payload.host
4. payload.observer_name
5. payload.vhost
6. payload.domain
7. payload.url_domain
8. source_config.device_name
9. source_config.source_name
10. source_name
11. source
12. Unknown
```

例:

```text
NASログに host = nas-01 がある
-> device_name / observer_name として nas-01 を表示する

Webログに vhost = example.com がある
-> domain / vhost として example.com を表示する

YAMAHAルーターログに機器名が無い
-> source_config.source_name があれば YAMAHAルーター と表示する
-> source_config も無ければ Unknown と表示する

RTX1210 という機種名がログにも設定にも無い
-> RTX1210 とは表示しない
```

---

### 0.6 Dashboard は source_type を主役にしない

Dashboard の主役は `source_type` ではない。

Dashboard の主軸は以下とする。

```text
ログソース
ホスト / デバイス
ドメイン / vhost
送信元IP
ユーザー
URLパス
イベント種別
HTTPステータス
```

`source_type` は内部分類として使ってよい。
ただし、Dashboard のメイン表示を `source_type別` のグラフだけにしてはいけない。

---

### 0.7 UI は Tabler を使う

フロントエンド UI は Tabler をベースにする。

Tabler:

```text
https://github.com/tabler/tabler
```

Tabler のダッシュボードテンプレート、カード、テーブル、バッジ、タブ、サイドバー、ページヘッダー、フォーム、ドロップダウンを活用する。

単に ECharts のグラフを並べただけの画面にしない。

Tabler らしい管理画面として、以下を使う。

```text
ページヘッダー
統計カード
ステータスバッジ
フィルター付きテーブル
タブ付き詳細画面
サイドバーナビゲーション
パンくず
ドロップダウン操作
空状態表示
エラー状態表示
```

---

## 1. システム概要

本システムは、API または TCP で受信した JSON イベントを蓄積し、調査担当者がログを検索・確認・相関できるようにする。

目的:

```text
JSONイベントを受信する
payload を保存する
payload の中身を確認する
ログソース単位で状況を見る
ホスト / デバイス単位で状況を見る
ドメイン / vhost 単位で状況を見る
送信元IP、ユーザー、URL、MAC、リソースで相関する
コメントやタグを付ける
インシデントに紐付ける
ルールベースの注意喚起を表示する
```

本システムは、最初から高度な検知・自動対応を行う SIEM ではない。
ただし、将来 SIEM 的に使えるよう、軽量タクソノミーとエンティティ抽出を持つ。

---

## 2. 入力方式

### 2.1 REST API ingest

JSONイベントを REST API で受信する。

エンドポイント例:

```text
POST /ingest
POST /ingest/{source}
POST /ingest/bulk
```

対応する入力:

```text
単一JSONオブジェクト
JSON配列
```

受信時に付与するメタデータ:

```text
received_at
ingest_channel = api
source
source_name
source_type
receiver_ip
api_key_id
parser_name
parser_version
```

---

### 2.2 TCP JSON ingest

TCP で JSON Lines / NDJSON を受信する。

形式:

```text
1行 = 1 JSONイベント
newline-delimited JSON
NDJSON
```

例:

```json
{"time":"2026/04/06 00:18:51","tag":"DHCPD","message":"LAN1(port1) Extends 192.168.0.111: 00:00:5e:00:53:af"}
```

要件:

```text
TCP listener を backend 内に実装する
受信ポートは環境変数または設定ファイルで変更可能にする
不正JSONは dead_letters に保存する
送信元IPを receiver_ip として保存する
source / source_type は設定により決定する
```

---

### 2.3 API Pull connector

将来拡張として、外部 API から定期取得する connector を追加できる構造にする。

対象例:

```text
Microsoft 365
Microsoft Entra ID
Google Workspace
Exchange Online
SharePoint Online
Teams
各種SaaS監査ログ
```

connector で取得したイベントも、内部的には ingest pipeline に流す。

---

## 3. ingest pipeline

すべての入力は、以下の共通処理を通る。

```text
受信
  ↓
JSON検証
  ↓
source / source_name / source_type 判定
  ↓
events.payload へ保存
  ↓
timestamp 抽出
  ↓
parser 適用
  ↓
taxonomy mapping
  ↓
entity extraction
  ↓
rule evaluation
  ↓
検索・画面表示可能状態へ
```

---

## 4. payload と正規化

### 4.1 payload

payload は、受信した JSON イベント本文である。
形式は source ごとに異なってよい。

例:

```json
{
  "vhost": "example.com",
  "client": "198.51.100.23",
  "time": "23/Apr/2026:12:09:35 +0900",
  "request": "GET /wp-content/index.php HTTP/2",
  "status": "404",
  "user_agent": "Mozilla/5.0 ..."
}
```

payload は PostgreSQL の JSONB に保存する。

---

### 4.2 軽量タクソノミー

payload のキー名はログ種別によって異なる。
そのため、検索・集計・相関に使う項目は、payload の外側に正規化フィールドとして保存する。

正規化できない項目は `null` でよい。
無理に推定しすぎない。

---

## 5. source / source_name / source_type

### 5.1 source

`source` は内部的なソース識別子である。

例:

```text
google_workspace
yamaha_router
nas_01
example_dev
logw
kantsuri
```

---

### 5.2 source_name

`source_name` は画面表示用の名前である。

例:

```text
Google Workspace
YAMAHAルーター
NAS nas-01
example.com
logw
kantsuri
Unknown
```

Dashboard や Events 一覧では、`source_name` を優先表示する。

ログ内に機器名が無い場合でも、`source_config.source_name` に設定があればそれを表示する。
設定も無い場合は `Unknown` と表示する。

---

### 5.3 source_type

`source_type` は意味分類である。
形式名ではない。

使用可能な source_type:

```text
web_access
web_error
google_workspace_audit
m365_audit
entra_signin
router
nas
auth
application
system
unknown
```

禁止:

```text
syslog
```

`syslog` は source_type として使わない。

---

## 6. 軽量タクソノミー項目

### 6.1 event 系

```text
event_time
event_time_original
event_time_confidence
event_category
event_type
event_action
event_result
event_severity
event_reason
message
```

event_category の例:

```text
authentication
web
network
audit
system
application
security
unknown
```

event_result:

```text
success
failure
unknown
not_applicable
```

ただし、Dashboard では `event_result` を主役にしない。
初期段階では `unknown` が多くなりやすいため、補助情報として扱う。

---

### 6.2 source / observer 系

```text
source
source_name
source_type
ingest_channel
observer_name
observer_type
device_name
service_name
```

意味:

```text
source_name   : 画面表示用のログソース名
observer_name : ログを出した機器やサービス
device_name   : ルーター、NASなどのデバイス名
service_name  : process、tag、アプリ名など
```

ログに存在しない `device_name` を勝手に推定しない。
ログにも設定にも無ければ `Unknown` とする。

---

### 6.3 actor / user 系

```text
actor_user
actor_ip
actor_host
target_user
user_name
```

---

### 6.4 network 系

```text
source_ip
source_port
destination_ip
destination_port
network_protocol
network_transport
mac_address
```

---

### 6.5 host / domain 系

```text
host_name
target_host
observer_name
device_name
url_domain
vhost
```

注意:

`host` という1項目にすべてを押し込まない。

Webログの `vhost` はドメイン / 仮想ホストである。
NASやルーターの `host` は機器名である。
意味が異なるため、画面でも分けて表示する。

---

### 6.6 Web 系

```text
url_domain
vhost
url_path
url_query
http_method
http_status_code
http_user_agent
http_referer
request
```

Webログでは、Dashboard と Events 一覧に `url_domain` または `vhost` を必ず表示する。

---

### 6.7 resource / file 系

```text
resource_id
resource_type
resource_name
target_resource
file_path
file_name
request_id
```

---

## 7. DB設計

### 7.1 events

受信 JSON イベントを保存する。

```text
events
- id
- received_at
- ingest_channel
- source
- source_name
- source_type
- receiver_ip
- payload JSONB
- payload_hash
- parser_name
- parser_version
- parse_status
- parse_error
- created_at
```

---

### 7.2 normalized_events

検索・集計・表示用の正規化フィールドを保存する。

```text
normalized_events
- event_id
- event_time
- event_time_original
- event_time_confidence

- event_category
- event_type
- event_action
- event_result
- event_severity
- event_reason
- message

- source_name
- source_type
- observer_name
- observer_type
- device_name
- service_name

- actor_user
- actor_ip
- actor_host

- source_ip
- source_port
- destination_ip
- destination_port
- network_protocol
- network_transport
- mac_address

- host_name
- target_host
- target_user
- target_resource

- url_domain
- vhost
- url_path
- url_query
- http_method
- http_status_code
- http_user_agent
- http_referer
- request

- resource_id
- resource_type
- resource_name
- file_path
- file_name
- request_id
```

---

### 7.3 event_entities

相関検索用のエンティティを保存する。

```text
event_entities
- id
- event_id
- entity_type
- entity_value
- role
- confidence
- extractor_name
- created_at
```

entity_type:

```text
ip
user
host
device
mac
domain
url
path
file
resource
request_id
email
process
```

role:

```text
actor
source
destination
target
observer
related
unknown
```

---

### 7.4 annotations

イベントに対するコメント・タグを保存する。

```text
annotations
- id
- event_id
- comment
- tags
- created_by
- created_at
- updated_at
```

---

### 7.5 incidents

インシデント情報を保存する。

```text
incidents
- id
- title
- status
- severity
- summary
- owner
- created_at
- updated_at
```

status:

```text
open
investigating
benign
false_positive
resolved
archived
```

---

### 7.6 incident_events

インシデントとイベントの紐付けを保存する。

```text
incident_events
- id
- incident_id
- event_id
- added_by
- added_at
- note
```

---

### 7.7 dead_letters

不正 JSON や取り込み失敗イベントを保存する。

```text
dead_letters
- id
- received_at
- ingest_channel
- source
- source_name
- source_type
- receiver_ip
- raw_text
- error_type
- error_message
- created_at
```

---

### 7.8 source_configs

source ごとの設定を保存する。

```text
source_configs
- id
- source
- source_name
- source_type
- device_name
- enabled
- parser_name
- mapping_name
- description
- created_at
- updated_at
```

source_config は、payload に機器名や表示名が存在しない場合の補助設定として使う。

例:

```text
source = yamaha_router
source_name = YAMAHAルーター
source_type = router
device_name = YAMAHAルーター
```

もし機種名を明示できる場合のみ、`device_name = RTX1210` のように設定してよい。
ログにも設定にも無い場合は、勝手に機種名を推定しない。

---

### 7.9 mapping_configs

payload key と taxonomy field の対応を保存する。

```text
mapping_configs
- id
- name
- source_type
- config_json JSONB
- version
- enabled
- created_at
- updated_at
```

---

### 7.10 assets

ユーザーが明示的に登録したグローバルIP資産を保存する。
ローカル(プライベート)IPは動的に自動判定するため、このテーブルへの登録は不要
（判定ルールは 10.7 Assets を参照）。

```text
assets
- id
- ip
- ip_version
- label
- description
- created_by
- created_at
- updated_at
```

ip_version:

```text
v4
v6
```

---

## 8. parser / extractor / mapping

### 8.1 parser

parser は source_type ごとに payload を解釈する。

parser 例:

```text
google_workspace_parser
m365_audit_parser
web_access_parser
web_error_parser
yamaha_router_parser
nas_parser
auth_parser
application_log_parser
generic_json_parser
```

禁止:

```text
syslog_parser を画面分類として使わない
```

仮に内部実装で syslog 由来の変換ロジックが必要な場合でも、画面上の source_type や表示名には出さない。

---

### 8.2 extractor

extractor はログ種別に依存しない汎用抽出処理である。

```text
timestamp_extractor
ip_extractor
ipv6_extractor
mac_extractor
email_extractor
url_extractor
path_extractor
request_id_extractor
http_request_extractor
user_extractor
domain_extractor
```

---

### 8.3 mapping 例

```yaml
google_workspace_audit:
  event_time:
    - 日付
  actor_user:
    - アクター
  source_ip:
    - IP アドレス
  event_action:
    - イベント
  message:
    - 説明
  target_resource:
    - リソース

web_access:
  source_ip:
    - client
  url_domain:
    - vhost
  vhost:
    - vhost
  request:
    - request
  http_status_code:
    - status
  http_user_agent:
    - user_agent
  http_referer:
    - referer

web_error:
  event_time:
    - time
  event_severity:
    - level
  service_name:
    - context
  message:
    - message

router:
  event_time:
    - time
  service_name:
    - tag
  message:
    - message

nas:
  event_time:
    - time
  observer_name:
    - host
  device_name:
    - host
  service_name:
    - process
  message:
    - message

application:
  event_time:
    - time
  event_severity:
    - level
  service_name:
    - context
  message:
    - message
```

---

## 9. API設計

### 9.1 ingest API

```text
POST /ingest
POST /ingest/{source}
POST /ingest/bulk
```

---

### 9.2 events API

```text
GET /api/events
GET /api/events/{id}
GET /api/events/{id}/payload
GET /api/events/{id}/normalized
GET /api/events/{id}/entities
GET /api/events/{id}/related
```

---

### 9.3 dashboard API

```text
GET /api/dashboard/summary
GET /api/dashboard/timeline
GET /api/dashboard/sources
GET /api/dashboard/hosts
GET /api/dashboard/domains
GET /api/dashboard/top-ips
GET /api/dashboard/top-users
GET /api/dashboard/top-url-paths
GET /api/dashboard/http-status
GET /api/dashboard/event-actions
```

---

### 9.4 field / mapping API

```text
GET /api/fields
GET /api/fields/by-source
GET /api/mappings
POST /api/mappings/test
POST /api/mappings
PUT /api/mappings/{id}
```

---

### 9.5 entities API

```text
GET /api/entities
GET /api/entities/{type}/{value}
GET /api/entities/{type}/{value}/events
GET /api/entities/{type}/{value}/timeline
```

---

### 9.6 assets API

```text
GET /api/assets
GET /api/assets/{ip}
POST /api/assets
PUT /api/assets/{id}
DELETE /api/assets/{id}
```

ローカル(プライベート)IPは自動判定して一覧に含めるため、登録系エンドポイントの対象は
グローバルIPのみでよい。

---

### 9.7 admin API

```text
GET /api/admin/ingest-status
GET /api/admin/dead-letters
GET /api/admin/sources
POST /api/admin/sources
GET /api/admin/parsers
GET /api/admin/tcp-listeners
```

---

## 10. 画面設計

### 10.1 左メニュー

左メニューは以下とする。

```text
Dashboard
Events
Sources
Hosts / Domains
Assets
Entities
Correlations
Fields
Mappings
Ingest
Dead Letters
Incidents
Rules
Admin
```

---

### 10.2 Dashboard

Dashboard は、source_type を主役にした汎用グラフ画面にしない。
調査の入口として、ログソース・ホスト・ドメイン・エンティティを中心にする。

上部カード:

```text
総イベント数
直近24時間イベント数
取り込み失敗数
ログソース数
ホスト/ドメイン数
```

メイン表示:

```text
ログソース別カード一覧
ホスト / デバイス別ランキング
ドメイン / vhost別ランキング
時系列グラフ（ログソース別）
上位送信元IP
上位ユーザー
上位URLパス
HTTPステータス別
イベント種別別
```

表示してはいけないもの:

```text
syslog という分類
source_type だけを主役にしたグラフ
unknown だらけの result グラフ
ログに存在しない機器名の勝手な推定表示
```

Dashboard 画面イメージ:

```text
+--------------------------------------------------------------------------------+
| Dashboard                                                                       |
+--------------------------------------------------------------------------------+
| 総イベント | 直近24時間 | 取り込み失敗 | ログソース数 | ホスト/ドメイン数        |
+--------------------------------------------------------------------------------+
| ログソース別                                                                  |
| [Google Workspace] [YAMAHAルーター] [NAS nas-01] [example.com]         |
+--------------------------------------------------------------------------------+
| 時系列（ログソース別）                                                         |
| [graph]                                                                        |
+--------------------------------------------------------------------------------+
| ホスト/デバイス別              | ドメイン/vhost別                               |
| NAS nas-01               | example.com                                  |
| YAMAHAルーター                 | logw                                           |
| Unknown                        | kantsuri                                       |
+--------------------------------------------------------------------------------+
| 上位送信元IP                   | 上位URLパス                                    |
+--------------------------------------------------------------------------------+
| HTTPステータス別               | イベント種別別                                  |
+--------------------------------------------------------------------------------+
```

---

### 10.3 Events

Events はメインのログ検索画面である。

検索条件:

```text
時間範囲
全文検索
ログソース
種別
ホスト / デバイス
ドメイン / vhost
送信元IP
ユーザー
イベント
URLパス
HTTPステータス
タグ
インシデント有無
任意 payload key=value
```

標準カラム:

```text
時刻
ログソース
種別
ホスト/デバイス
ドメイン/vhost
送信元IP
ユーザー
イベント
対象
ステータス
メッセージ
タグ
インシデント
```

Events 画面イメージ:

```text
+--------------------------------------------------------------------------------+
| Events                                                                         |
+--------------------------------------------------------------------------------+
| Time [Last 24h] Source [All] Host/Domain [All] IP [____] Search [___________]   |
+--------------------------------------------------------------------------------+
| 時刻 | ログソース | 種別 | ホスト/デバイス | ドメイン/vhost | IP | イベント | Msg |
+--------------------------------------------------------------------------------+
| ...  | example.com | Webアクセス | - | example.com | 23.101... | GET... |
| ...  | Google Workspace | 監査 | - | - | 240b:... | 監査と調査のクエリ | ... |
| ...  | YAMAHAルーター | ルーター | YAMAHAルーター | - | - | DHCPD | ... |
| ...  | NAS nas-01 | NAS | nas-01 | - | - | CRON | ... |
+--------------------------------------------------------------------------------+
```

---

### 10.4 Event Detail

1イベントの詳細画面。

タブ:

```text
概要
Payload
正規化フィールド
抽出エンティティ
相関イベント
コメント・タグ
インシデント
Parser情報
```

概要表示:

```text
時刻
ログソース
種別
ホスト/デバイス
ドメイン/vhost
送信元IP
ユーザー
イベント
対象
ステータス
メッセージ
```

Payload タブ:

```text
受信 JSON payload を整形表示する
JSON ツリー表示
キー検索
値コピー
```

---

### 10.5 Sources

ログソース単位で確認する画面。

表示項目:

```text
source
source_name
source_type
device_name
件数
最終受信時刻
parser
mapping
parse_success_rate
```

例:

```text
Google Workspace
YAMAHAルーター
NAS nas-01
example.com
logw
kantsuri
Unknown
```

---

### 10.6 Hosts / Domains

ホスト・デバイス・ドメインを確認する画面。

タブ:

```text
Hosts / Devices
Domains / vhosts
```

Hosts / Devices:

```text
NAS nas-01
YAMAHAルーター
Unknown
```

Domains / vhosts:

```text
example.com
logw
kantsuri
```

---

### 10.7 Assets（アセット / 資産）

自社が保有するIP資産を確認する画面。Entities（ログ上で観測された全IP）とは異なり、
「自分たちの資産かどうか」を軸にした一覧である。

対象:

```text
ローカルIP（プライベートアドレス）: 自動判定。登録不要
グローバルIP（自前のVPS/クラウド/オフィス回線等）: ユーザーが手動登録
```

ローカルIP自動判定ルール（IPv4）:

```text
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
127.0.0.0/8
169.254.0.0/16
```

ローカルIP自動判定ルール（IPv6）:

```text
fc00::/7   (Unique Local Address)
fe80::/10  (link-local)
::1        (loopback)
```

上記レンジに一致する IP entity は、登録なしで自動的に資産として一覧表示する。
上記に一致しないグローバルIPは、ユーザーが assets（7.10）に登録したものだけ資産として
表示する。未登録のグローバルIPは Assets には表示されず、Entities側で通常のIPエンティティ
として（区分：未登録/グローバル）確認できる。

表示項目:

```text
IP
IPバージョン（v4 / v6）
区分（ローカル / 登録済みグローバル）
ラベル（登録時のみ）
初回出現
最終出現
出現回数
関連ホスト/デバイス
```

---

### 10.8 Entities

ログ上で観測された全ての識別子（IP・ユーザー・MAC・ドメイン等）を対象にした
調査・相関用の一覧画面である。**自社の資産一覧ではない**。アクセス元IPや外部ホストの
IPも区別なく含まれる。ローカルIPおよび登録済みグローバルIPの資産としての確認は
Assets（10.7）を参照する。

IP、ユーザー、MAC、URL、リソースを軸に調査する画面。

対象:

```text
IP
User
Host
Device
MAC
Domain
URL
Path
Resource
Request ID
Email
```

Entity detail では以下を表示する。

```text
初回出現
最終出現
出現回数
関連ログソース
関連イベント
タイムライン
イベント一覧
```

---

### 10.9 Correlations

相関イベントを確認する画面。

相関理由:

```text
same_source_ip
same_actor_user
same_device
same_host
same_domain
same_url_path
same_mac
same_resource
same_request_id
near_time
```

最初はグラフ表示ではなく、相関理由つき一覧でよい。

---

### 10.10 Fields

payload に含まれるフィールドを探索する画面。

表示項目:

```text
ログソース
種別
payload key
出現件数
出現率
型推定
代表値
マッピング先
```

目的:

```text
未知のJSON形式を把握する
未マッピング項目を見つける
mapping候補を作る
```

---

### 10.11 Mappings

payload key と taxonomy field の対応を管理する画面。

機能:

```text
payload key を taxonomy field に割り当てる
正規表現抽出を設定する
timestamp形式を設定する
mappingテストを行う
mapping versionを管理する
```

---

### 10.12 Ingest

API / TCP 受信状態を確認する画面。

表示項目:

```text
REST API ingest 状態
TCP listener 状態
受信ポート
最終受信時刻
source別受信件数
失敗件数
dead letter件数
```

---

### 10.13 Dead Letters

不正 JSON や取り込み失敗を確認する画面。

表示項目:

```text
受信時刻
ingest_channel
source
source_name
source_type
receiver_ip
error_type
error_message
raw_text
```

---

## 11. ルールベース注意喚起

初期段階では自動検知ではなく、注意喚起として扱う。

例:

```text
短時間に大量の404
.php ファイル探索
/wp-admin/ 探索
wp-config へのアクセス
PHP Warning 大量発生
ログイン失敗連続
監査ログの検索
監査ログのエクスポート
管理系イベント
VPN / IKE セッション断続
同一MACのIP変化
```

---

## 12. 初期対応ログ種別

### 12.1 Webアクセス

想定 payload:

```text
vhost
client
time
request
status
size
referer
user_agent
raw
```

正規化:

```text
source_ip        <- client
url_domain       <- vhost
vhost            <- vhost
request          <- request
http_method      <- requestから抽出
url_path         <- requestから抽出
http_status_code <- status
http_user_agent  <- user_agent
event_category   <- web
event_action     <- http_request
```

---

### 12.2 Webエラー / アプリケーションエラー

想定 payload:

```text
time
level
pid
context
message
raw
```

正規化:

```text
event_time     <- time
event_category <- application
event_type     <- error
event_action   <- php_warning / app_error
service_name   <- context
message        <- message
```

---

### 12.3 Google Workspace監査

想定 payload:

```text
日付
イベント
説明
アクター
IP アドレス
リソース
```

正規化:

```text
event_time      <- 日付
event_action    <- イベント
message         <- 説明
actor_user      <- アクター
source_ip       <- IP アドレス
target_resource <- リソース
event_category  <- audit
source_name     <- Google Workspace
source_type     <- google_workspace_audit
```

---

### 12.4 YAMAHAルーター

想定 payload:

```text
time
tag
message
raw
```

正規化:

```text
event_time       <- time
source_name      <- source_config.source_name があればそれを使う。なければ YAMAHAルーター または Unknown
source_type      <- router
device_name      <- payload に device_name / hostname / host があればそれを使う。なければ source_config.device_name。なければ Unknown
service_name     <- tag
event_category   <- network
event_action     <- tag/messageから推定
network_protocol <- DHCP / IKE など
source_ip        <- messageから抽出できる場合
mac_address      <- messageから抽出できる場合
message          <- message
```

注意:

```text
payload に RTX1210 が無い場合、RTX1210 とは表示しない。
source_config に device_name = RTX1210 と明示されている場合のみ表示してよい。
```

---

### 12.5 NAS

想定 payload:

```text
time
host
process
pid
message
raw
```

正規化:

```text
event_time     <- time
source_type    <- nas
source_name    <- NAS + host
observer_name  <- host
device_name    <- host
service_name   <- process
message        <- message
event_category <- system / authentication / file など
```

---

### 12.6 認証ログ

source_type:

```text
auth
```

正規化:

```text
event_category <- authentication
actor_user
source_ip
event_action
event_result
message
```

---

## 13. MVP ロードマップ

### MVP 1: API/TCP JSONイベントビューア

```text
POST /ingest
TCP JSON listener
events.payload JSONB 保存
source / source_name / source_type 付与
timestamp抽出
Dashboard
Events
Event Detail
Dead Letters
```

---

### MVP 2: Dashboard 修正

```text
ログソース別カード
ホスト/デバイス別ランキング
ドメイン/vhost別ランキング
時系列（ログソース別）
上位送信元IP
上位URLパス
HTTPステータス別
イベント種別別
```

`syslog` は一切表示しない。

---

### MVP 3: 軽量タクソノミー

```text
normalized_events
event_time
source_name
source_type
observer_name
device_name
url_domain
vhost
source_ip
actor_user
event_action
http_status_code
message
```

---

### MVP 4: エンティティ抽出と相関

```text
event_entities
IP抽出
ユーザー抽出
ホスト抽出
MAC抽出
ドメイン抽出
URL抽出
エンティティ画面
相関イベント一覧
assets（ローカルIP自動判定 + グローバルIP手動登録）
Assets画面
```

---

### MVP 5: 調査支援

```text
コメント
タグ
インシデント
ルールベース注意喚起
検索結果エクスポート
インシデントレポート
```

---

## 14. 非目標

初期実装では以下は行わない。

```text
ユーザーによるJSONファイルアップロード
原本ログファイル管理
高度なAI分析
機械学習による異常検知
自動遮断
自動対応
SOAR機能
商用SIEM相当の検知ルール管理
ログに存在しない機器名の勝手な推定表示
```

---

## 15. 実装上の注意

### 15.1 画面に `syslog` を出さない

分類、凡例、フィルター、グラフ、テーブルに `syslog` を表示しない。

---

### 15.2 source_type は意味分類にする

source_type は形式名ではない。
利用者が調査で理解できる意味分類にする。

---

### 15.3 機器名はログまたは設定にある場合のみ表示する

payload に機器名がある場合はそれを表示する。
payload に無い場合は source_config の値を使う。
payload にも source_config にも無い場合は `Unknown` とする。

ログにも設定にも無い値を parser が勝手に作ってはいけない。

---

### 15.4 Dashboard は調査入口にする

Dashboard はグラフを雑に並べる画面ではない。
ログソース、ホスト、ドメイン、IP、ユーザー、URLを起点に調査へ進める画面にする。

---

### 15.5 Tabler を活かす

Tabler のカード、テーブル、バッジ、ページヘッダー、タブ、サイドバーを使う。
単純なグラフ集ではなく、管理画面として使いやすい UI にする。

---

### 15.6 正規化できなくても保存する

parser が完全に解釈できなくても payload は保存する。
parse_status を `partial` または `failed` として扱う。

---

### 15.7 null / Unknown を許容する

すべてのログに以下が存在するとは限らない。

```text
source_ip
actor_user
host_name
device_name
url_path
event_result
```

存在しない場合は `null` または `Unknown` とする。
無理に推定しすぎない。

---

## 16. 最終的な方向性

本システムは、以下を目指す。

```text
API/TCP JSON Event Collector
+ Lightweight Taxonomy Normalizer
+ Entity Correlation Viewer
+ Investigation Workspace
```

重要な思想:

```text
JSONファイルアップロード型ではない。
受信した JSON payload を保存する。
syslog を分類として扱わない。
source_type は意味分類にする。
機器名はログまたは設定にある場合だけ表示する。
無ければ Unknown でよい。
Dashboard はログソース・ホスト・ドメイン・IP・ユーザーを主軸にする。
Tabler を使い、調査しやすい UI にする。
```
