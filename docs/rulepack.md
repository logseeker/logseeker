# ルールパック（宣言型の検知ルール）

検知ルールを Python のコードではなくデータ（YAML）で書き、共通エンジン（`backend/app/rulepack.py`）で評価する仕組み。

- 同梱パック: `backend/app/rulepacks/builtin.yaml`（現在は Windows の12ルール・GitLab の3ルール）
- コードで書いた組み込みルール（`rules.py` の `RULE_DEFS`）も引き続き使う。IOC照合・ログ未達のように、
  他テーブルとの突き合わせや時刻計算が必要で宣言型では書けないものはコードに残している
- 監視ルール一覧（`/api/rules`）と注意喚起（`/api/rule-hits`）・通知には、両方がまとめて出る

## 方針

将来、ルールパックを外部（例: `rule.logseeker.jp`）から配信できるようにする前提で、次の性質を持たせている。
現時点では外部からの取得は実装しておらず、同梱パックだけを読む。

| 性質 | 内容 |
|---|---|
| コードを実行しない | ルールに書けるのは条件・集約キー・しきい値・証跡の項目だけ。SQLはエンジンが組み立て、値はすべてバインド変数で渡す |
| Taxonomy外KEYを使わない | `key` に書けるのは `docs/taxonomy.md` のKEYだけ。手元のTaxonomyに無いKEYを使うルールは読み込まない |
| 1ルールの不備で全体を止めない | 検証に失敗したルールはそのルールだけ読み込まない（理由はログに出る）。評価中の失敗も同様 |
| 重い問い合わせで止まらない | 1ルールの評価に `statement_timeout`（10秒）をかける。超えたらそのルールだけ飛ばす |
| 外部から受け取るパックは署名必須 | Ed25519署名を `rulepack.verify_signature()` で検証してから読む。同梱パックはアプリのコードと同じ扱いのため署名不要 |
| 知らない形式は読まない | `format` がエンジンの対応版と違うパックは丸ごと読まない（新しい形式を古いエンジンが誤解釈しないため） |

## 書式（format: 1）

```yaml
format: 1
pack: builtin              # パック名
version: "2026.10.02-1"    # パックの版

rules:
  - id: win_pass_the_hash             # 英小文字・数字・_（3〜64文字）。組み込みルールと重複不可
    name: "[Windows] Pass-the-Hashの疑い"   # 監視ルール一覧に出る名前
    title: Pass-the-Hashの疑い          # 注意喚起の見出し（「<title>: <集約キーの値>」になる）。省略時は name
    severity: high                      # critical / high / warning / info
    category: security                  # security / operations
    description: ...                    # 監視ルール一覧の説明
    recommendation: ...                 # 対策
    scope: {source_type: windows_event, event_action: ["4624"]}   # 必須。正規化列だけで対象を絞る
    match: ...                          # 条件（省略時は scope に入る行すべて）
    group_by: [source_ip, host_name]    # 集約キー（先頭から順に、最初に値がある列）
    threshold: {count: 1}               # しきい値（省略時は count: 1）
    evidence:                           # 証跡に並べる項目（6項目まで）
      - {label: 対象アカウント, key: targetusername}
      - {label: ログオン先, col: host_name}
```

### 値の参照: `key` と `col`

| 書き方 | 参照するもの |
|---|---|
| `key: logontype` | 受信payloadの Taxonomy KEY。照合は大文字小文字を区別しない（`LogonType` も一致） |
| `col: source_ip` | 正規化済みの列。使える列は `rulepack.COLS`（source / source_type / event_category / event_action / event_result / source_ip / source_country / actor_user / host_name / device_name / service_name / url_domain / url_path / http_status_code / message） |
| `key: [commandline, newprocessname]` | リスト。条件では「どれか1つが満たせば一致」、証跡では「最初に値があるもの」 |

値は比較の前に前後の空白を除く。空文字と `-`（Windowsイベントの「値なし」）は値が無いものとして扱う。

### 条件: `match`

`all`（すべて）/ `any`（どれか）/ `not`（否定）で組み合わせる。入れ子は6段、条件の数は60個まで。

```yaml
match:
  all:
    - {key: ticketencryptiontype, eq: "0x17"}
    - not: {key: servicename, endswith: "$"}
    - {key: servicename, ne: krbtgt}
```

| 演算子 | 意味 | 値が無い行 |
|---|---|---|
| `eq` / `ne` | 一致 / 不一致（大文字小文字を区別しない） | eq は不一致、ne は一致 |
| `in` / `not_in` | いずれかに一致 / どれにも一致しない（値はリスト） | in は不一致、not_in は一致 |
| `contains` / `startswith` / `endswith` | 部分一致 / 前方一致 / 後方一致（`%` `_` はエスケープされる） | 不一致 |
| `regex` | 正規表現（PostgreSQL の `~*`）。リストならどれか1つに一致 | 不一致 |
| `exists` | `true` で値がある / `false` で値が無い | — |
| `ip_global` | `true` でグローバルIP / `false` でそれ以外（プライベート・ループバック・文書用等）。IPとして読めない値はグローバルでない扱い | グローバルでない |

正規表現の制約: 1パターン300文字まで、1条件40パターンまで。**`\b` は使えない**（PostgreSQLでは単語境界ではなく
後退文字の意味になる）。読み込み時に Python の `re` で構文を検査する。

### 集約: `group_by`

1〜3列。「関連イベントを見る」で Events を絞り込むキーになるため、使えるのは
source / source_ip / actor_user / host_name / device_name / service_name / url_domain / source_country / event_action。
複数書くと先頭から順に、最初に値がある列で集約する（例: `[source_ip, host_name]` は送信元IPが無いイベントをホスト名でまとめる）。

### しきい値: `threshold`

| 書き方 | 意味 |
|---|---|
| `{count: 10}` | 集約キーごとの件数が10件以上 |
| `{distinct: {col: actor_user}, min_distinct: 5}` | 集約キーごとに、異なる actor_user が5種類以上 |

両方書いた場合は両方を満たしたときに発火する。1ルールあたりの注意喚起は件数の多い順に50件まで。

### 証跡: `evidence`

| 項目 | 内容 |
|---|---|
| `label` | 表示名 |
| `key` / `col` | 並べる値 |
| `show` | `values`（既定。値を重複除去して並べる）/ `count`（種類数を出す） |
| `limit` | 並べる値の数（1〜5、既定3）。超えた分は「ほかN件」 |
| `truncate` | 1つの値の最大文字数（10〜500、既定160） |

末尾に必ず「N 件」が付く。例: `対象アカウント: admin / ログオン先: TEST-PC01 / 1 件`

## 署名

外部から配信するパックは、配信元で秘密鍵により署名し、各LogSeekerは公開鍵で検証する。
公開鍵は複数受け付ける（鍵を入れ替える期間に新旧どちらの署名も通すため）。

```bash
# 鍵の生成（秘密鍵ファイルを権限600で作り、公開鍵を表示する。既存ファイルは上書きしない）
python backend/tools/rulepack_sign.py keygen rulepack-signing.key
# 署名（rules.yaml.sig を作る）
python backend/tools/rulepack_sign.py sign rules.yaml rulepack-signing.key
# 検証
python backend/tools/rulepack_sign.py verify rules.yaml rules.yaml.sig <公開鍵(base64)>
```

- **秘密鍵はリポジトリ（公開）にコミットしない。** 公開鍵は公開してよい
- ライセンスキーのHMAC（`license.py`）は検証側も秘密を持つ方式のため、ルール配信には使わない
- 署名検証には `cryptography` を使う。検証するときだけ読み込むので、同梱パックしか使わない環境では未導入でも動く

## 外部配信へ進めるときに足すもの（未実装）

1. 定期取得（`ioc_sync.py` と同じ形。取得 → 署名検証 → 形式検証 → DBへ保存）
2. 前回取得した正常なパックを使い続ける仕組み（取得失敗・検証失敗時。初回は同梱パック）
3. 環境ごとの上書き（ルールの有効/無効・しきい値）を手元に保存し、配信で更新されても消えないようにする
4. 管理画面に「パックの版・最終取得日時・読み込みを見送ったルール」を表示
5. 公開鍵の設定（環境変数など）と、配信元の秘密鍵の保管

## ルールを追加・変更するとき

1. `builtin.yaml` を編集する（新しいKEYが必要なら、先に `docs/taxonomy.md` に追加して `taxonomy_master.py` を再生成する）
2. 開発環境でバックエンドが再読み込みされたら、ログに `rule skipped` が出ていないか確認する
3. 模擬イベントを投入して、発火すべきケースで発火し、発火すべきでないケースで発火しないことを確認する
4. `version` を上げてコミットする
