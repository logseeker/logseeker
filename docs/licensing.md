# ライセンス（データ保持期間の制御）

**ログ種別（source_type）による機能制限、及びAPIオプション（M365/Google Workspace等コネクタ）の制限は撤廃した。
全ログ種別・APIオプションは、ライセンスキーの有無にかかわらず無償で利用できる。**

ライセンスキーの仕組みは、**データ保持期間の延長**（既定90日 → 1年/3年/無制限）にのみ使われる。
延長の詳細・使い方は [docs/retention.md](retention.md) を参照。

## ライセンスキーの発行（保持期間延長用、ベンダー側）
HMAC 署名付きキー。`LICENSE_SECRET`（環境変数）を共有するインスタンスで検証可能。**本番は必ず `LICENSE_SECRET` を変更**。

```bash
# 例: ライセンシー名、365日、保持期間1年（backendのvenvを有効化した状態、または venv/bin/python で直接実行）
cd backend && ../venv/bin/python -m app.tools.issue_license --name "ACME Inc" --days 365 --retention-days 365
```

## 適用（利用者側）
- 画面「ライセンス」→ キーを貼り付けて「適用」。または `POST /api/license {"key":"..."}`。
- 未適用時は既定の保持期間90日が使われる（[docs/retention.md](retention.md)）。

## 関連設定（.env）
```ini
LICENSE_SECRET=（本番は長いランダム文字列）
```
