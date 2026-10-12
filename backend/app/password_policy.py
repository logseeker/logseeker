"""管理者パスワードの要件（パスワード認証は管理者専用。管理者以外はSSOなので対象外）。

根拠は日本政府の推奨（docs/auth.md「パスワードの要件」）:
- 内閣サイバーセキュリティセンター(NISC)「インターネットの安全・安心ハンドブック」P.34:
  英大文字・小文字・数字・記号の計88種類をランダムに使い、10桁以上を推奨
- 総務省「国民のためのサイバーセキュリティサイト」: 最低でも10文字以上、数字・記号・大文字・小文字の混在
これを最低ラインとし、満たさないものはすべて「要件を満たしていない」として扱う。

文字は半角の英数字・記号（ASCIIの表示可能文字。空白は不可）に限る。全角文字は入力環境によって
打てない・別の文字に化けることがあり、管理者が締め出される原因になるため。

既に設定済みのパスワード（初期パスワード等）は平文を持たないため、ログイン時に判定する。
満たしていなければ password_change_required を立て、変更するまで他の操作をさせない（main.py）。
フロント側の表示（frontend/src/passwordPolicy.tsx）も同じ規則にそろえること。
"""
import secrets
import string

MIN_LENGTH = 10
SYMBOLS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"  # ASCIIの記号32種


def violations(password: str) -> list[str]:
    """満たしていない要件の一覧（空なら要件を満たす）。"""
    pw = password or ""
    out = []
    if len(pw) < MIN_LENGTH:
        out.append(f"{MIN_LENGTH}文字以上")
    if not any(c in string.ascii_uppercase for c in pw):
        out.append("英大文字（A-Z）を含む")
    if not any(c in string.ascii_lowercase for c in pw):
        out.append("英小文字（a-z）を含む")
    if not any(c in string.digits for c in pw):
        out.append("数字（0-9）を含む")
    if not any(c in SYMBOLS for c in pw):
        out.append("記号（!#$% 等）を含む")
    if any(not (c in string.ascii_letters or c in string.digits or c in SYMBOLS) for c in pw):
        out.append("半角の英数字・記号のみ（空白・全角文字は不可）")
    return out


def is_compliant(password: str) -> bool:
    return not violations(password)


def error_message(password: str) -> str | None:
    v = violations(password)
    return None if not v else "パスワードが要件を満たしていません（" + "、".join(v) + "）"


def generate(length: int = 16) -> str:
    """要件を満たすランダムなパスワード（仮パスワードのメール送付用）。
    紛らわしい文字（0/O, 1/l/I）と、メール本文で崩れやすい記号は避ける。"""
    upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    lower = "abcdefghijkmnopqrstuvwxyz"
    digits = "23456789"
    symbols = "!#$%&*+-=?@"
    pool = upper + lower + digits + symbols
    chars = [secrets.choice(upper), secrets.choice(lower), secrets.choice(digits), secrets.choice(symbols)]
    chars += [secrets.choice(pool) for _ in range(max(length, MIN_LENGTH) - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
