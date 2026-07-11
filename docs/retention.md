# データ保持期間（LogSeeker）

## 何をするか
このアプリの**DB上のイベント（events / normalized_events / event_entities）と取り込み失敗（dead_letters）**を、
一定日数を過ぎたら**自動的に削除**します。バックグラウンドの定期処理（6時間おきに判定）が行います。

> ⚠️ **あくまで「このアプリのDBから消す」だけ**です。送信元の機器・NXLog・syslogサーバー等、
> 他のシステムに保存されたログには一切触れません（セルフホスト前提・自己完結）。

## 既定値
- **既定は 90日**（ログ種別・APIオプションに関係なく共通）。
- 90日を過ぎた受信データは自動的にDBから削除されます。

## 延長する場合（拡張ライセンス）
「保持期間の上書き」を、ライセンスキーに含めて発行できます（ログ種別・APIオプションは無償で全開放済みのため、
保持期間の延長がライセンスキーの唯一の用途です）。

```sh
# backendのvenvを有効化した状態、または venv/bin/python で直接実行
# 1年保持
../venv/bin/python -m app.tools.issue_license \
  --name "顧客名" --days 365 --retention-days 365

# 3年保持
../venv/bin/python -m app.tools.issue_license \
  --name "顧客名" --days 365 --retention-days 1095

# 無制限（自動削除しない）
../venv/bin/python -m app.tools.issue_license \
  --name "顧客名" --days 365 --retention-days -1
```

- 発行したキーは「ライセンス」画面から適用（DBが正）。
- 現在の設定は「ライセンス」画面・「システム状態」画面で確認できます。

## 仕組み（実装）
- `backend/app/retention.py` … 6時間おきにチェックし、`received_at` が保持期限を過ぎた `events` / `dead_letters` を削除。
  `events` を削除すると外部キー（`ondelete=CASCADE`）で `normalized_events` / `event_entities` も連動して消えます。
- `backend/app/license.py` の `retention_days()` … 適用中ライセンスの `retention_days`（null なら既定90日、`-1` なら無制限）。
- 監査ログ・ユーザーアカウント等（アプリ自身の管理データ）は対象外（別ポリシー、無期限保持）。
