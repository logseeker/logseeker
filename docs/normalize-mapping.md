# LogSeeker 受信フィールド・表示／集計優先順位仕様 v1.7

- 更新日: 2026-08-12
- マスター: `docs/normalize-mapping.md`
- 上位文書: `PROJECT.md`（最新の基本設計）
- 関連仕様: `docs/taxonomy.md`
- 注記: ファイル名は既存設計との連続性のため `normalize-mapping.md` を維持するが、**LogSeeker受信後のKEY変換・正規化マッピングは行わない**。

## 0. 文書の位置づけ

本書はLogSeeker基本設計の下位に位置する**共通仕様・マスター**であり、Taxonomy受信フィールドをEvents / Dashboardで表示・検索・集計する際の共通ルールを定義する。

- 受信フィールド名、意味、型、日本語表示名は `docs/taxonomy.md` を正とする。
- 基本設計と本書が矛盾する場合は、**基本設計を正として本書を修正する。**
- `docs/taxonomy.md` に存在しないpayload KEYを、本書独自の受信フィールドとして追加してはならない。

## 1. 目的

LogSeekerは任意のJSON KEYを受信し、payload全体をKEY名・VALUE・階層とも無改変で保存する。

ただし、Eventsの表示・検索、Dashboardの表示・集計、Rule / Correlation / Entity / GeoIP等で機能対象となる**受信フィールドは `docs/taxonomy.md` のTaxonomy KEYと完全一致するKEYだけ**とする。

本書は、そのTaxonomy受信フィールドをEvents / Dashboardでどのように表示・集計するかを定義する。

## 2. 最重要原則

### 2.1 受信payloadは改変しない

LogSeekerは受信後に以下を行ってはならない。

- KEY名の変更
- KEYの削除
- KEYの追加
- 別KEYへのVALUEコピー
- KEY同士の統合
- VALUEの書き換え
- VALUEの推測・補完
- `vhost` → `virtualhost` のような読み替え
- `client` → `srcipv4` のような読み替え
- GeoIP、Entity、Rule、Correlation等の派生結果を受信payloadへ混入すること

### 2.2 受信フィールドはTaxonomy KEYだけ

用語を次のとおり固定する。

```text
受信payload
  = 受信したJSON全体
  = Taxonomy KEY + Taxonomy外KEYを含む

受信フィールド
  = 受信payload内で docs/taxonomy.md のKEYと完全一致したKEY
  = 表示・検索・集計・解析等の機能対象

Taxonomy外KEY
  = 受信payload内には保存する
  = それ以外は何もしない
```

Taxonomy外KEYは、以下の対象にしてはならない。

- Events表示候補
- フィールド検索、全文検索、ファセット等の検索対象
- Dashboard表示・集計候補
- Rule / Correlation / Entityの入力
- GeoIP等の解析入力
- 検索用インデックスや機能用派生フィールドへの展開

Taxonomy外KEYは受信payloadとして保存容量を消費するだけの未利用データとして扱う。

### 2.3 `class` もTaxonomy受信フィールド

`class` は `docs/taxonomy.md` に定義された `string` 型のTaxonomy KEYである。Class名は受信JSONの `class` VALUEそのものとする。

LogSeekerは他のKEYからClassを推測せず、受信した `class` のVALUEを読み替え・変換・補完しない。`class` が存在しない場合も `unknown` 等を自動追加しない。

### 2.4 管理メタデータ・派生メタデータは別体系

`source` / `source_name` / `received_at` 等のLogSeeker管理メタデータ、およびTaxonomy受信フィールドを入力として生成するGeoIP等の派生メタデータは、受信フィールドとは別体系である。各詳細設計に従って表示・検索・フィルタへ利用してよいが、受信payloadへ書き戻してはならない。`class` は管理メタデータではなく受信フィールドである。

## 3. Taxonomyの役割

`docs/taxonomy.md` は、LogSeekerの受信フィールド名の唯一のマスターである。

新規にNXLog等の設定を作れる場合は、例えば次のTaxonomy KEYを使用する。

```text
アクセス日時      → eventtime
接続元IPv4       → srcipv4
接続元IPv6       → srcipv6
HTTPメソッド      → httpmethod
URI              → uri
HTTPステータス    → statuscode
```

ログ送信元が次のようなTaxonomy外KEYを送っても受信自体は行う。

```json
{
  "vendor_client_ip": "192.168.1.12",
  "vendor_site": "example.com"
}
```

`vendor_client_ip` / `vendor_site` は `docs/taxonomy.md` に定義されていないため、payloadへ保存するだけで表示・検索・集計・解析には使用しない。`srcipv4` / `vhost` / `virtualhost` 等のTaxonomy KEYを新規生成したり、VALUEをコピーしたりしてはならない。

LogSeekerで利用したい値は、ログ送信元が適切なTaxonomy KEYを選択して送信する。

## 4. Eventsのフィールド表示・検索

### 4.1 表示候補は実際に受信したTaxonomy KEYだけ

Eventsの表示フィールド候補は、選択中の `class` VALUE等で実際に受信しているKEYのうち、`docs/taxonomy.md` に完全一致する受信フィールドだけとする。

Taxonomy KEYの場合は `docs/taxonomy.md` の日本語表示名・説明を利用する。Taxonomy外KEYは表示候補へ出さない。

### 4.2 検索対象もTaxonomy KEYだけ

受信payloadを対象とするフィールド検索、全文検索、ファセット、絞り込み等はTaxonomy受信フィールドだけを対象とする。Taxonomy外KEY名およびそのVALUEは検索対象にしない。

管理メタデータ・派生メタデータの検索可否は各詳細設計に従う。

### 4.3 LogSeeker利用者による表示／非表示

LogSeeker利用者は、表示候補となったTaxonomy受信フィールドをチェックボックス等で表示／非表示にできる。

最低限、次を保存できるようにする。

- 表示するフィールド
- 表示しないフィールド
- 表示順序
- 対象 `class` VALUE

表示設定を変更しても受信payloadは変化しない。

### 4.4 複数のTaxonomy KEYが存在する場合

例えば次のJSONを受信した場合:

```json
{
  "domain": "example.com",
  "virtualhost": "site-a",
  "hostname": "host.example.net",
  "vhost": "legacy-site"
}
```

`domain` / `vhost` / `virtualhost` / `hostname` はすべてTaxonomy KEYなので、受信JSONに存在する各KEYを表示・検索候補にできる。

```text
domain       = example.com
vhost        = legacy-site
virtualhost  = site-a
hostname     = host.example.net
```

各KEYは独立して扱い、`vhost` を `virtualhost` へ読み替える等の変換は行わない。

## 5. VALUEがない場合

受信JSONが次の場合:

```json
{
  "domain": "example.com"
}
```

機能対象となる受信フィールドは、実際に存在する `domain` だけである。

```text
domain        = example.com
vhost         = 未存在
virtualhost   = 未存在
virtualdomain = 未存在
host          = 未存在
hostname      = 未存在
```

LogSeekerは不足フィールドを補完しない。

## 6. Dashboardの関連フィールド優先順位

### 6.1 目的

Dashboardでは「ドメイン／ホスト」等を横断的に一覧表示するため、**Taxonomyに定義された関連KEYだけ**を候補として、表示・集計時に代表値優先順位を設定できる。

この優先順位はデータ変換ではない。受信payloadを変更せず、どのTaxonomy受信フィールドを代表値として先に見るかを決めるだけである。

### 6.2 ドメイン／ホスト候補の初期優先順位

初期設定は次を基準とする。

```text
domain
  > vhost
  > virtualhost
  > virtualdomain
  > host
  > hostname
```

`domain` / `vhost` / `virtualhost` / `virtualdomain` / `host` / `hostname` はすべてTaxonomy KEYとして候補にできる。

### 6.3 代表値

例:

```text
domain        = example.com
vhost         = example.com
virtualhost   = site-a
host          = host.example.net
hostname      = node.example.net
```

代表値は、優先順位で最初に見つかった空でないVALUEであるため、この場合は次となる。

```text
domain = example.com
```

`vhost` / `virtualhost` / `host` / `hostname` はTaxonomy受信フィールドとして残り、追加表示候補にできる。

### 6.4 異なるVALUEを追加表示する場合

```text
domain        = example.com
vhost         = other-vhost.example
virtualhost   = other.example
host          = host.example.net
hostname      = node.example.net
```

代表値は `domain = example.com` とする。LogSeeker利用者は、`vhost = other-vhost.example`、`virtualhost = other.example`、`host = host.example.net`、`hostname = node.example.net` を追加表示・集計対象として選択できる。

追加表示候補もTaxonomy受信フィールドだけとする。

### 6.5 同一VALUEの重複表示

```text
domain        = example.com
vhost         = example.com
virtualhost   = example.com
```

この場合、代表値は `domain = example.com` とし、同一イベントの `example.com` を同じDashboardグループで二重計上しない。

これは表示上の重複排除であり、受信フィールドの削除やpayload変更ではない。

### 6.6 Dashboardのチェックボックス

LogSeeker利用者は、Taxonomy関連フィールドごとにDashboardでの追加表示／集計対象を選択できる。

例:

```text
☑ domain
☑ vhost
☑ virtualhost
☐ virtualdomain
☐ host
☐ hostname
```

Taxonomy外KEYをチェック項目へ出さない。チェック状態はLogSeeker利用者ごとに保存できる構造とする。

## 7. DashboardからEventsへの遷移

Dashboardに表示されたドメイン／ホスト／IP等をクリックすると、その表示・集計に含まれていたEvents一覧へ遷移できるようにする。

### 7.1 代表値グループをクリックした場合

例えば優先順位が次の場合:

```text
domain > vhost > virtualhost > virtualdomain > host > hostname
```

Dashboardの代表値 `example.com` には、次のイベントが同じグループへ含まれ得る。

```text
イベントA: domain = example.com
イベントB: domain = 未存在, vhost = example.com
イベントC: domain/vhost = 未存在, virtualhost = example.com
イベントD: domain/vhost/virtualhost = 未存在, virtualdomain = example.com
イベントE: domain/vhost/virtualhost/virtualdomain = 未存在, host = example.com
イベントF: domain/vhost/virtualhost/virtualdomain/host = 未存在, hostname = example.com
```

この代表値をクリックした場合は、Dashboard集計時と同じ優先順位判定をEvents絞り込みにも適用する。

概念上の条件は次のとおり。

```text
(domain = example.com)
OR (domain が空/未存在 AND vhost = example.com)
OR (domain/vhost が空/未存在 AND virtualhost = example.com)
OR (domain/vhost/virtualhost が空/未存在 AND virtualdomain = example.com)
OR (domain/vhost/virtualhost/virtualdomain が空/未存在 AND host = example.com)
OR (domain/vhost/virtualhost/virtualdomain/host が空/未存在 AND hostname = example.com)
```

これはTaxonomy受信フィールドに対する検索条件であり、KEY変換・コピー・保存処理ではない。

### 7.2 追加表示フィールドをクリックした場合

追加表示したTaxonomy受信フィールドは、そのKEY名とVALUEをそのまま条件にする。

例えば `virtualhost = other.example` をクリックした場合:

```text
field = virtualhost
value = other.example
```

Taxonomy外KEYをDashboardに表示しないため、Taxonomy外KEYを起点にEventsへ遷移する導線も作らない。

## 8. `class` との関係

`class` はイベントの種類・ログソースを識別するTaxonomy受信フィールドであり、受信KEYの変換規則ではない。

EventsやDashboardの表示設定を `class` VALUEごとに変えてよいが、それはUI設定である。TaxonomyのClass別参考例に載っていないKEYでも、全KEY一覧に存在し受信payloadに同名KEYがあれば機能対象にできる。

他のKEYの存在から `class` VALUEを決めてはならない。`class` が存在しない場合もLogSeekerは補完しない。

Taxonomy外KEYは `class` VALUEに関係なく受信・保存のみとする。

## 9. Mappings画面の見直し

現行Mappings画面が「受信JSON KEY → 別の標準KEY」への変換を前提としている場合、その仕様は廃止対象とする。

今後の画面は、少なくとも次を扱える構成を検討する。

- Taxonomy受信フィールド一覧
- 日本語表示名・説明
- Eventsの初期表示候補
- Dashboard関連フィールドグループ
- Dashboardでの代表値優先順位
- Dashboard追加表示の初期ON/OFF

Taxonomy外KEYを表示・検索・集計設定の対象として列挙しない。

画面名称を `Mappings` のまま維持するか、`Fields` / `Display Rules` 等へ整理するかは、既存画面・API・ルーティングへの影響調査後に決定する。

## 10. 永続化

受信後KEY変換用のマッピング設定は新規に持たない。

永続化が必要なのは、主に次の設定である。

- LogSeeker利用者ごとのEvents表示フィールド設定
- LogSeeker利用者ごとのDashboard追加表示チェック状態
- Dashboardの関連フィールドグループと代表値優先順位の既定値

既存 `mapping_configs`、`user_settings`、`normalized_events` 等をどのように整理するかは、既存DB・API・backend・frontend・本番データを調査してから決定する。

不要となる旧マッピング設定・旧カラム・旧APIを新旧二重で無期限に残さない。

## 11. 現行実装への移行

現行 `backend/app/normalize.py` 等に固定のKEY読み替え処理や、Taxonomy外KEYを検索・表示・解析へ展開する処理が存在する場合、いきなり削除せず、以下を調査する。

- 現在の受信payloadの実際のKEY
- `docs/taxonomy.md` との一致状況
- 現在のDB保存値・検索用データ
- Events / Dashboard / Rule / Correlation / Entity / GeoIPからの参照
- `/api/mappings` 等のAPI利用箇所
- Mappings画面の利用箇所
- 過去データとの互換性

移行後の正仕様は次のとおり。

```text
全KEYをpayloadへ無改変保存
Taxonomy KEYに一致したKEYだけを受信フィールドとして機能対象化
Taxonomy外KEYはpayload保存のみ
```

必要なデータ移行・旧ロジック削除は、影響調査後に明示的に実施する。

## 12. 受入条件

1. 受信payloadが受信時の内容から変更されない。
2. 受信KEYが別KEYへ読み替え・コピー・補完されない。
3. Taxonomy KEYに一致したKEYだけが受信フィールドとして表示・検索・集計・解析対象になる。
4. Taxonomy外KEYはpayloadに保存されるが、表示・検索・集計・Dashboard・Rule・Correlation・Entity・GeoIP等では使用されない。
5. Taxonomy外KEYのVALUEは全文検索・フィールド検索・ファセット等にも出ない。
6. `domain` / `vhost` / `virtualhost` / `virtualdomain` / `host` / `hostname` はすべてTaxonomy KEYであり、受信した各KEYを独立して機能対象にできる。
7. `domain` しかない場合、LogSeekerが `vhost` / `virtualhost` / `virtualdomain` / `host` / `hostname` 等を補完しない。
8. EventsでLogSeeker利用者が、実際に受信したTaxonomy KEYの表示／非表示・表示順を選択できる。
9. Dashboardのドメイン／ホスト初期優先順位は `domain > vhost > virtualhost > virtualdomain > host > hostname` とする。
10. Dashboardで異なるTaxonomy関連VALUEを追加表示するフィールドをLogSeeker利用者が選択できる。
11. 同一VALUEが複数Taxonomy関連フィールドに存在する場合、Dashboardで同一イベントを二重計上しない。
12. Dashboardの代表値クリック時は集計時と同じTaxonomy関連フィールド優先順位でEventsを絞り込む。
13. 追加表示した個別Taxonomyフィールドをクリックした場合は、そのKEY名とVALUEをそのままEvents条件にする。
