# GeoIP（送信元IPの国コード表示）

## 何ができるか
送信元IP（`source_ip`）から**国コード**（例: `JP`, `CN`, `US`）を判定し、イベント一覧に表示、
「海外からのアクセス」ルール（`foreign_access`、日本以外からのアクセスを検知）を有効化します。

**MongoDBは不要です。** 使うのは MaxMind 社が無償配布している **GeoLite2-Country.mmdb** という
1ファイルのローカルデータベース（数MB）だけです。ネットワーク不要・完全オフラインで動きます。

## セットアップ手順（無料）
1. MaxMind の無料アカウントを作成: https://www.maxmind.com/en/geolite2/signup
2. ログイン後、「GeoLite2 / Download Files」から **GeoLite2-Country** の `.mmdb` 形式をダウンロード
   （アカウントの「My License Key」から license key を発行し、直接ダウンロードリンクを使う方法もあります）
3. ダウンロードした `GeoLite2-Country.mmdb` を `.env` の `GEOIP_DB_PATH` が指すパスに置く
   （既定は `backend/geoip/GeoLite2-Country.mmdb`。[INSTALL.md](../INSTALL.md) の配置例では `/opt/logseeker/backend/geoip/`）
4. バックエンドを再起動
   ```sh
   sudo systemctl restart logseeker-backend
   ```
5. 以降、新しく取り込まれるイベントから国コードが付与されます
   （**既に取り込み済みのイベントには遡って付与されません**。再取り込みが必要な場合は `load_logs --reset`）。

## 確認方法
- イベント一覧の「送信元IP」列に国コードのバッジが表示されます。
- 「ルール / 注意喚起」で `foreign_access`（海外からのアクセス）が検知対象になります。
- mmdb を置かない場合は、今まで通り国コードは表示されず、`foreign_access` ルールも該当0件のままです
  （エラーにはなりません＝オプショナル機能）。

## 定期更新について
MaxMindのデータベースは更新されるため、正確性を保つには定期的な再ダウンロードが望ましいです
（無料版は月1〜2回更新）。運用では `geoipupdate` ツールの利用や、cronでの定期再取得を検討してください
（このアプリ自体は自動更新しません。ファイルを差し替えて `sudo systemctl restart logseeker-backend` するだけです）。

## 実装
- `backend/app/geoip.py` … mmdbがあれば `geoip2` ライブラリで国コードを引く。無ければ常に `None`。
- `backend/app/pipeline.py` … 取り込み時に `source_ip` があれば国コードを判定し `source_country` に保存。
- `backend/app/rules.py` … `foreign_access` ルールで `source_country != "JP"` を検知（`HOME_COUNTRY` 定数で変更可）。
