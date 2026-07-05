# 使い方マニュアル（LogSeeker）

## 0. 全体像：2階建て構造
LogSeeker は **受け取ったJSONを無改変で保存**し、その外側に **正規化(normalized)** を派生させる。
機能は「どちらの階に依存するか」で、対応できるログの範囲が変わる。

| 階 | 中身 | どんなログでも効くか |
|----|------|----------------------|
| **① 汎用エクスプローラ** | 全文検索 / フィールド自動ファセット / ランキング / レコード一覧・原文表示 | **YES。どんなJSONでも動く**（キー構成不問） |
| **② 正規化ベース機能** | イベント一覧の整形列 / エンティティ / 相関分析 / ルール・注意喚起 / 通知 | **正規化フィールドが埋まった時だけ**動く（下記条件） |

---

## 1. 「全く関係ないサイト/他人のログ」でも機能するか

### 結論
- **①汎用エクスプローラは、どんなJSONでもそのまま機能する**（保存・検索・ファセット・集計・原文表示）。
- **②相関分析・エンティティ・ルールは、正規化フィールド（送信元IP・ユーザー・ドメイン等）が埋まって初めて機能する。**
  埋まるかどうかは「送られてくるJSONのキー」次第。

### なぜか
相関やエンティティは魔法ではなく、`source_ip` `actor_user` `url_domain` `device_name` 等の
**正規化フィールドを軸にSQLで突き合わせているだけ**（AIなし）。
このフィールドが null のままだと、相関する“軸”が無いので出てこない。

正規化フィールドが埋まる条件は次のいずれか：
1. **JSONのキーが、その種別(source_type)の候補キーに一致**する
   （画面「マッピング」で一覧。NXLogのPascalCase や `client`/`user`/`status` 等の一般名に対応）
2. キーが違っても、**メッセージ本文中にIP/MACがあれば**汎用抽出で `source_ip`/`mac_address` は拾える
3. その種別の**マッピングが未定義**（例：独自アプリの `source_type=myapp`）なら、正規化フィールドは基本 null
   → ①の全文検索・ファセットでは見えるが、②の相関・エンティティ・ルールには出ない

### ケース別まとめ
| 送られてくるもの | ①検索/ファセット | ②相関/エンティティ/ルール |
|---|---|---|
| NXLogでJSON化した標準ログ（syslog/secure/messages/Windows/Apache等） | ◎ | ◎（マッピング済みの種別で自動的に効く） |
| 一般的なキー名(`client_ip`,`user`,`status`…)を持つ独自JSON | ◎ | ○（キーがマッピング候補に合えば効く。合わなければ×） |
| 全く独自のキーのアプリログ（`source_type`未対応） | ◎ | △（本文にIPがあればIP相関のみ。他は×） |
| キーも中身もバラバラな任意JSON | ◎ | ×（軸が無い。①で探索する用途になる） |

### 新しいログ種別を②でも活かしたいとき
`backend/app/normalize.py` の `MAPPINGS` に
「その種別のフィールド → 候補キー」を1ブロック足せば、相関・ルールの対象になる。
（画面「マッピング」の表がそのままこの設定の可視化。CSVでも出力可）

> 要するに：**「見る・探す」だけなら何でも来い。「相関・攻撃検知」は、キーが分かっている（=マッピングがある）ログでこそ真価を発揮**、という設計。

---

## 2. NXLog から TCP 516 の JSON で送る

### 結論：**その通り。TCP 516 で NDJSON（1行=1JSON）を送れば受信・保存・正規化される。** 動作確認済み。

- 受信ポート：`TCP_INGEST_PORT`（既定 **516**）。1接続で複数行OK、**1行につき1つのJSON**（NDJSON / JSON Lines）。
- 不正な行は破棄せず **取り込み失敗(dead_letter)** に隔離（他の行の取り込みは継続）。
- 送信元IPは `receiver_ip` に自動記録。

### 重要：`source_type` を必ず入れる
LogSeeker は JSON本文の中の **`source_type`**（と任意で `source`）を見て種別を決める。
NXLog標準のJSONにはこのキーが無いので、**NXLog側で付与**する。これが無いと種別=null扱いになり、
②の相関・ルールが効かない（①の検索は効く）。

対応する種別値（画面「マッピング」「ライセンス」と同じ）：
`web_access` `web_error` `linux` `auth` `system` `nas` `mail` `windows_event` `router` など。

### NXLog 設定例（Linux secure/messages を送る）
```
<Extension json>
    Module      xm_json
</Extension>

<Input in_secure>
    Module      im_file
    File        '/var/log/secure'
</Input>

<Output out_tcp>
    Module      om_tcp
    Host        <LogSeekerのIP>
    Port        516
    Exec        $source_type = "linux";      \
                $source = "linux-secure";     \
                to_json();                    # 1行1JSONで送出（NDJSON）
</Output>

<Route r1>
    Path        in_secure => out_tcp
</Route>
```
- `$source_type`(必須) と `$source`(任意の表示ラベル) を `to_json()` の前にセットするのがポイント。
- Windowsなら `im_msvistalog` + `$source_type="windows_event"`、Apacheなら `$source_type="web_access"` 等。

### 送信テスト（NXLog無しでも確認できる）
```sh
printf '%s\n' '{"source_type":"linux","source":"test","Hostname":"h1","SourceName":"sshd","Message":"Failed password for root from 203.0.113.5 port 22 ssh2"}' \
  | nc <LogSeekerのIP> 516
```
→ イベント一覧に種別=Linux / 送信元IP=203.0.113.5 / ユーザー=root / 失敗 として現れる（実測確認済み）。

### 送信経路の選択
| 経路 | 用途 | 認証 |
|---|---|---|
| **TCP 516 (NDJSON)** | NXLog等からの常時転送 | （本番は）ネットワーク到達制御。将来的にTLS/トークン化 |
| **REST `POST /ingest`** | アプリ/バッチからの送信、単発・配列可 | `INGEST_TOKEN`（Bearer）で保護可 |

> 公開運用時のポート/認証の締め方は [security.md](security.md) を参照。
