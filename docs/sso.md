# SSO（シングルサインオン）— Google Workspace / Microsoft 365

## 概要
- 方式は **OpenID Connect（Authorization Code フロー + PKCE）**。対応IdPは **Google Workspace** と **Microsoft 365（Entra ID）**。
- **本人確認・MFA（多要素認証）・パスワード管理はIdPに任せる。** LogSeekerはSSOユーザーのパスワードを持たない。
  - MFAの強制は利用者側のIdPで設定する（Google Workspace：2段階認証プロセスの適用／Entra ID：セキュリティの既定値群・条件付きアクセス）。
  - 退職者などはIdP側でアカウントを停止すれば、LogSeekerにもログインできなくなる（発行済みセッションは最長 `SESSION_HOURS` まで有効。即時に止める場合はユーザー管理で無効化する）。
- **個人アカウントは対象外。**
  - Google：許可ドメイン（Workspaceの `hd` クレーム）が必須。`gmail.com` は指定できない。
  - Microsoft：特定のテナントが必須。`common` / `organizations` / `consumers` は指定できない。
- **自動プロビジョニングはしない。** 管理者が事前に「SSOユーザー」を作成した人だけがログインできる。
- **管理者はSSOの対象外**（ID／パスワード＋2段階認証。[docs/auth.md](auth.md)）。SSOで入れるのは管理者以外のロール（システム管理者・編集者・閲覧者）。管理者アカウントはIdPの障害時の非常口も兼ねる。
- 必要なのは「LogSeekerのサーバーからIdP（accounts.google.com / login.microsoftonline.com）へ HTTPS で出られること」だけ。Dockerでもネイティブ配置でも同じように動く。

## ユーザーの種類
| 認証方式 | ログイン方法 | パスワード |
|---|---|---|
| パスワード（管理者のみ） | ユーザー名＋パスワード＋2段階認証（TOTP） | LogSeekerが保持（pbkdf2） |
| SSO（管理者以外） | ログイン画面の「Google でログイン」「Microsoft 365 でログイン」 | **持たない**（パスワードではログインできない。管理者も設定できない） |

- SSOユーザーは作成時に **IdPでログインするメールアドレス** を登録する。
- 初回SSOログイン時、IdPが返す確認済みメールアドレス（Google：`email`＋`email_verified`／Microsoft：`preferred_username`(UPN) または `email`）と一致したユーザーに、IdPのアカウントID（`sub`）を紐付ける。
- 2回目以降は紐付けた `sub` で照合する（IdP側でメールアドレスが変わっても影響しない）。
- ユーザー管理で「メール変更」または「紐付け解除」をすると紐付けが外れ、次回ログイン時に登録メールアドレスで再照合する（IdP側でアカウントを作り直した場合など）。

## 設定手順

### 1. 公開URLの確認
LogSeekerを利用者がブラウザで開くURL（例 `https://logseeker.example.com`）。リダイレクトURIはこれから組み立てる：
- Google：`<公開URL>/api/sso/google/callback`
- Microsoft：`<公開URL>/api/sso/microsoft/callback`

本番は **https 必須**（IdP側もlocalhost以外のhttpは受け付けない）。

### 2. Google Workspace
1. Google Cloud コンソール →「APIとサービス」→「OAuth 同意画面」：ユーザーの種類は **内部**（Workspace組織内のみ）を推奨。
2. 「認証情報」→「認証情報を作成」→「OAuth クライアント ID」→ 種類 **ウェブ アプリケーション**。
3. 「承認済みのリダイレクト URI」に上記のGoogle用URIを登録。
4. 表示されたクライアントID・クライアントシークレットを控える。
5. Workspace管理コンソールで、対象ユーザーに2段階認証プロセスを適用（MFAの強制）。

### 3. Microsoft 365（Entra ID）
1. Entra 管理センター →「アプリの登録」→「新規登録」。
   - サポートされているアカウントの種類：**この組織ディレクトリのみに含まれるアカウント（シングルテナント）**。
   - リダイレクトURI：プラットフォーム **Web**、上記のMicrosoft用URI。
2. 「概要」の **アプリケーション(クライアント)ID** と **ディレクトリ(テナント)ID** を控える。
3. 「証明書とシークレット」→「新しいクライアント シークレット」→ 値を控える（**有効期限があるので更新を忘れないこと**）。
4. 「APIのアクセス許可」は既定の `User.Read`（委任）のままでよい（`openid` `email` `profile` を要求する）。
5. セキュリティの既定値群または条件付きアクセスでMFAを必須にする。

### 4. LogSeeker側
1. 管理パネル（`?screen=administration`）→「🔐セキュリティ設定」→「SSO」。
2. 公開URL、各IdPのクライアントID・シークレット、Googleは許可ドメイン、Microsoftはテナント（テナントID か `xxx.onmicrosoft.com`）を入力し、「有効」をONにして保存。
   - 画面に表示されるリダイレクトURIが、IdP側に登録した値と完全一致していることを確認する。
   - 設定が揃うと「ログイン画面に表示中」になる。
3. 「ユーザー管理」→「ユーザーを作成」→ 管理者以外のロールを選び、ユーザー名・**SSOのメールアドレス**を入力して作成（招待）。
4. 本人がログイン画面の「Google でログイン」/「Microsoft 365 でログイン」から入る。

## 実装（`backend/app/sso.py`）
1. `GET /api/sso/{provider}/login`：`state`・`nonce`・PKCE(`S256`)を生成してIdPへリダイレクト。
   ブラウザ束縛用のランダム値を `HttpOnly; SameSite=Lax; Path=/api/sso` のCookieに入れ、DB（`sso_login_states`）にはハッシュのみ保存（login CSRF対策。有効10分・一回限り）。
2. `GET /api/sso/{provider}/callback`：state・Cookie照合 → 認可コードをトークンに交換 → `id_token` を検証
   （IdPの公開鍵(JWKS)による署名・`iss`・`aud`・`exp`・`nonce`）→ ドメイン/テナント確認 → ユーザー照合。
   成功したら一回限り・60秒有効の交換コードを付けて `/?sso_code=...` へ戻す（セッショントークンをURLに載せないため）。
3. `POST /api/sso/exchange`：フロントが交換コード＋同じCookieでセッショントークン（従来と同じBearerトークン）を受け取る。
- ログインの成否は監査ログに `SSOログイン`（`login.sso`）として理由付きで残る。
- `/api/sso/...` はログイン前でも通す（認証必須ONでも）。設定APIは `/api/admin/sso`（admin専用・IPアクセス制限の対象）。
- 依存ライブラリは `PyJWT`（`cryptography` は既存）。HTTP通信は標準ライブラリ。

## ログイン失敗時の表示（理由コード）
| コード | 意味 |
|---|---|
| `not_registered` | SSOユーザーとして登録されていない（メールアドレス不一致を含む） |
| `domain` | Googleの許可ドメイン外、または個人のGoogleアカウント |
| `email` | IdPのメールアドレスが未確認／取得できない |
| `disabled` | ユーザーが無効化されている |
| `idp` | IdPの画面でキャンセルした、IdPのポリシーで拒否された |
| `state` / `expired` | 有効期限切れ・別ブラウザ・再送など |
| `token` | IdPの応答の検証に失敗（署名・発行者・宛先・nonce 等） |
| `config` | SSOの設定不足、またはIdPへ接続できない |

詳細な理由は監査ログの「内容」に記録される。
