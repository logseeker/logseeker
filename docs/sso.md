# SSO（シングルサインオン）について

## 結論：技術的に可能。Docker でもアプリ単体配布でも動く。現バージョンは「設定の受け口・保管」まで実装、実接続は未実装。

## なぜ単体配布でも可能か
SSO は「アプリ自身がIDを検証する」のではなく、**外部のIdP（IDプロバイダ）に委譲**する仕組み。
- 方式は **OpenID Connect (OIDC / Authorization Code フロー)** が標準的。
- IdP は **Google / Microsoft Entra ID(Azure AD) / Okta / Keycloak** などを利用者が用意。
- LogSeeker 側は「IdPのURL(issuer)・client_id・client_secret・redirect_uri」を設定するだけ。
- **必要なのは "アプリからIdPへ到達できるネットワーク" だけ**。Docker かどうかは無関係で、
  VPS に直接入れた単体アプリでも、利用者が自分のIdP情報を管理画面で設定すれば成立する。

つまり「アプリだけ配布」でも、**顧客が自社のIdPを繋ぐ**形で SSO は実現できる。
（LogSeeker が独自にID基盤を持つ必要はない。）

## 現在の実装状況
- 管理者(root)の「システム状態」→ セキュリティ設定に **SSO設定フォーム**を用意（保存可）。
- `sso.py` に設計と設定の保存/参照を実装。`implemented: false` を返し、実際の認可コードフローは未配線。
- ログイン画面には、SSO有効かつ実装済みのときだけ「SSOでログイン」ボタンを出す作り（現状は非表示）。

## 実装する場合の想定手順（次段階）
1. ライブラリ **Authlib**（OIDCクライアント）を backend に追加。
2. エンドポイント：
   - `GET /api/sso/login` … IdPの認可URLへリダイレクト（state/nonce付与）。
   - `GET /api/sso/callback` … 認可コード受領→トークン交換→`id_token`検証→`sub`/`email`取得。
3. ユーザー紐付け：`id_token.sub` を `users.sso_subject` に対応付け。
   - 初回は「許可ドメイン」チェックのうえ、設定ロール（既定 viewer）で**自動プロビジョニング**。
4. セッションは既存の Bearer トークン発行を流用（ローカル認証と同じ仕組みに合流）。
5. redirect_uri は `https://<自分のホスト>/api/sso/callback` を IdP 側にも登録。

## 補足
- SSO を使う場合も、非常用に **ローカルの root アカウントは残す**運用を推奨（IdP障害時のフォールバック）。
- 実運用は HTTPS 必須（OIDC はリダイレクトにトークンを載せるため）。→ [security.md](security.md)
