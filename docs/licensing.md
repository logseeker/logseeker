# ライセンス（機能制御）

発行されるライセンス（ティア＋APIオプション）によって、**取り込める＝使えるログ種別**を制御する。

## ティアとカテゴリ

| ティア | 名称 | 解放されるログ種別（source_type） |
|---|---|---|
| 1 | Web | `web_access` / `web_error` |
| 2 | Web + 監査 | + `auth`(セキュア/認証) / `system`(メッセージ/syslog) / `nas` / `mail` / `application` |
| 3 | + SMB/Windows/資産管理 | + `smb`(Windows Server/NAS) / `windows_event` / `asset`(SKYSEA等) |
| 4 | 制限なし | + `router` / `firewall`(FortiGate等) / `dns` / `dhcp`（ネットワーク機器） |
| OP | APIオプション | コネクタ取得：`google_workspace_audit` / `m365_audit` / `entra_signin`（M365・Google Workspace等を取りに行く） |

> 上位ティアは下位を内包。未知の source_type は最上位（Tier4）扱い。割り当ては `backend/app/license.py` の `CATEGORY_TIER` で変更可。

## 制御の効き方（機能制限・受信は拒否しない）
- 送られてきた JSON は**常に保存**する（受信側で送信は止められないため）。
- **未ライセンスの種別は画面・検索から除外**（選択肢に出ない／一覧・集計・ルールに出ない）。
  例：NASライセンスが無ければ、NASのJSONを送られても `nas`/`smb` 種別は選べず表示もされない。
- **上位ライセンスを適用すると、既に受信済みのデータがそのまま見えるようになる**（再取り込み不要）。
- **APIコネクタ**：`api` オプションが無いと M365/Google 等の取得・表示は不可。
- 画面「ライセンス」で現在のティア・有効期限・**種別ごとの利用可否**を確認、ライセンスキーを適用できる。

## ライセンスキーの発行（ベンダー側）
HMAC 署名付きキー。`LICENSE_SECRET`（環境変数）を共有するインスタンスで検証可能。**本番は必ず `LICENSE_SECRET` を変更**。

```bash
# 例: Tier3 + API、ライセンシー名、365日（backendのvenvを有効化した状態、または venv/bin/python で直接実行）
cd backend && ../venv/bin/python -m app.tools.issue_license --tier 3 --api --name "ACME Inc" --days 365
# → 出力されたキー文字列を顧客に渡す
```
オプション：`--tier 1..4` / `--api`（APIオプション）/ `--name` / `--days N`（0=無期限）。

## 適用（利用者側）
- 画面「ライセンス」→ キーを貼り付けて「適用」。または `POST /api/license {"key":"..."}`。
- 未適用時は環境変数 `LICENSE_DEFAULT_TIER`(既定1) / `LICENSE_DEFAULT_API`(既定false) が使われる。
  これが標準の既定（[LICENSE](../LICENSE) 第5条：正規ライセンスキー未適用時はWeb専用）。
  全機能を試したい場合はライセンスキーを発行して適用するか、ローカルでのみ一時的に値を上げること。

## 関連設定（.env）
```ini
LICENSE_SECRET=（本番は長いランダム文字列）
LICENSE_DEFAULT_TIER=1
LICENSE_DEFAULT_API=false
```
