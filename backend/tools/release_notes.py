"""リリースノート（backend/app/releases.json）に1件追加する。タグを打つ前に実行する。

アプリの「お知らせ」画面はこのファイルを読む（GitHubには取りに行かない）。リリースノートはコードと一緒に
配られるので、外部への通信やトークンは要らない。そのかわり、利用者が更新して初めてお知らせが出る。

本文は前回のタグ以降のコミットを「### 件名」＋本文で並べたもの（Co-Authored-By 行は除く）。
releases.json だけを変えたコミット（＝このツールで作るコミット）は数えない。

使い方（logseeker-public の直下で）:
    python3 backend/tools/release_notes.py v2026.11.21-1             # 追加して内容を表示
    python3 backend/tools/release_notes.py v2026.11.21-1 --dry-run   # 書き込まずに表示だけ
    git add backend/app/releases.json
    git commit -m "リリースノート v2026.11.21-1"
    git tag v2026.11.21-1

本文は追加後に releases.json を直接書き換えてよい（告知文を足す、言い回しを直す等）。
"""
import argparse
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

REPO = Path(__file__).resolve().parents[2]
NOTES = REPO / "backend" / "app" / "releases.json"
NOTES_REL = "backend/app/releases.json"
TAG_RE = re.compile(r"^v\d{4}\.\d{2}\.\d{2}(-\d+)?$")


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(REPO), *args], check=True,
                          capture_output=True, text=True, encoding="utf-8").stdout


def build_body(prev_tag: str | None) -> str:
    rng = f"{prev_tag}..HEAD" if prev_tag else "HEAD"
    # NULで区切って件名・本文を受け取る（本文に区切り文字が入っていても崩れないように）
    out = git("log", rng, "--no-merges", "--pretty=format:%s%x00%b%x00%x01", "--", ".", f":(exclude){NOTES_REL}")
    parts = []
    for rec in out.split("\x01"):
        rec = rec.strip("\n")
        if not rec:
            continue
        subject, body, *_ = rec.split("\x00") + ["", ""]
        lines = [ln for ln in body.splitlines() if not ln.startswith("Co-Authored-By:")]
        body = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()
        parts.append(f"### {subject.strip()}\n\n{body}".rstrip())
    return "\n\n".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tag", help="これから打つタグ（vYYYY.MM.DD または vYYYY.MM.DD-N）")
    ap.add_argument("--dry-run", action="store_true", help="releases.json を書き換えない")
    a = ap.parse_args()

    if not TAG_RE.match(a.tag):
        print(f"タグの形式が違います: {a.tag}（vYYYY.MM.DD または vYYYY.MM.DD-N）", file=sys.stderr)
        return 2
    if git("tag", "-l", a.tag).strip():
        print(f"タグ {a.tag} は既にあります", file=sys.stderr)
        return 2
    notes = json.loads(NOTES.read_text(encoding="utf-8")) if NOTES.exists() else []
    if any(r.get("tag_name") == a.tag for r in notes):
        print(f"{a.tag} は releases.json に既にあります（本文を直すならファイルを直接編集）", file=sys.stderr)
        return 2

    try:
        prev = git("describe", "--tags", "--abbrev=0", "HEAD").strip() or None
    except subprocess.CalledProcessError:
        prev = None
    body = build_body(prev)
    if not body:
        print(f"{prev or '最初'} 以降に releases.json 以外のコミットがありません", file=sys.stderr)
        return 1

    entry = {"tag_name": a.tag, "name": a.tag, "body": body,
             "published_at": datetime.now(ZoneInfo("Asia/Tokyo")).isoformat(timespec="seconds"),
             "prerelease": False}
    print(f"前回のタグ: {prev}\n\n{body}\n")
    if a.dry_run:
        return 0
    NOTES.write_text(json.dumps([entry] + notes, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"{NOTES_REL} に {a.tag} を追加しました。commit してからタグを打ってください。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
