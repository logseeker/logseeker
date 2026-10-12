// 管理者パスワードの要件（日本政府の推奨: NISC「インターネットの安全・安心ハンドブック」P.34 /
// 総務省「国民のためのサイバーセキュリティサイト」）。判定の正は backend/app/password_policy.py。
// ここは入力中にチェック表示するためのもので、同じ規則にそろえること。
export const PASSWORD_MIN_LENGTH = 10;
const SYMBOLS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
const isAllowed = (c: string) => /[A-Za-z0-9]/.test(c) || SYMBOLS.includes(c);

export const PASSWORD_RULES: { label: string; ok: (pw: string) => boolean }[] = [
  { label: `${PASSWORD_MIN_LENGTH}文字以上`, ok: (pw) => pw.length >= PASSWORD_MIN_LENGTH },
  { label: "英大文字（A-Z）を含む", ok: (pw) => /[A-Z]/.test(pw) },
  { label: "英小文字（a-z）を含む", ok: (pw) => /[a-z]/.test(pw) },
  { label: "数字（0-9）を含む", ok: (pw) => /[0-9]/.test(pw) },
  { label: "記号（!#$% 等）を含む", ok: (pw) => [...pw].some((c) => SYMBOLS.includes(c)) },
  { label: "半角の英数字・記号のみ（空白・全角文字は不可）", ok: (pw) => [...pw].every(isAllowed) },
];

export const isPasswordCompliant = (pw: string) => PASSWORD_RULES.every((r) => r.ok(pw));
export const PASSWORD_RULE_TEXT =
  `${PASSWORD_MIN_LENGTH}文字以上で、英大文字・英小文字・数字・記号をすべて含む（半角のみ）`;

// 入力欄の下に出すチェックリスト
export function PasswordChecklist({ password }: { password: string }) {
  return (
    <ul className="list-unstyled small mb-0">
      {PASSWORD_RULES.map((r) => {
        const ok = r.ok(password);
        return (
          <li key={r.label} className={ok ? "text-success" : "text-secondary"}>
            {ok ? "✓" : "・"} {r.label}
          </li>
        );
      })}
    </ul>
  );
}
