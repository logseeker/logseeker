"""docs/taxonomy.md から backend/app/taxonomy_master.py を生成する。

手打ち転記をやめ、設計書を機械的に読み取って生成する（taxonomy.mdが唯一のマスター。
v12 §0.0.1 / taxonomy.md §9 変更管理）。taxonomy.md を更新したらこのスクリプトを再実行する。

    python3 backend/tools/gen_taxonomy.py docs/taxonomy.md backend/app/taxonomy_master.py

抽出するもの:
  §3 標準タクソノミー 全KEY   → ALL_KEYS       選択可能なTaxonomy KEYの全体集合（Class非依存）
  §6.x Class VALUE別の参考例  → CLASS_HINTS    日本語表示名・初期表示フラグ（既定列の算出用）
"""
import re
import sys


def parse(md: str):
    all_keys: dict[str, str] = {}          # key -> 型
    labels: dict[str, str] = {}            # key -> 日本語表示名
    class_hints: dict[str, dict] = {}      # class -> {key: {"default_visible": bool}}

    section = None      # "all" / "class" / None
    cur_class = None

    for line in md.splitlines():
        h = re.match(r"^(#{2,3})\s+(.*)$", line)
        if h:
            title = h.group(2).strip()
            if title.startswith("3. 標準タクソノミー 全KEY"):
                section, cur_class = "all", None
            elif re.match(r"^6\.\d+\s+参考例:", title):
                section = "class"
                m = re.search(r"`([^`]+)`", title)
                cur_class = m.group(1) if m else None
                if cur_class:
                    class_hints.setdefault(cur_class, {})
            else:
                # 3.1 等の補足章、4章以降は表を拾わない
                section, cur_class = None, None
            continue

        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not cells or cells[0] in ("KEY", "---", ":---") or set(cells[0]) <= {"-", ":"}:
            continue
        km = re.match(r"^`([^`]+)`$", cells[0])
        if not km:
            continue
        key = km.group(1)

        if section == "all" and len(cells) >= 2:
            all_keys[key] = cells[1].strip("`")
        elif section == "class" and cur_class and len(cells) >= 4:
            # | KEY | 表示名 | 型 | 初期表示 | 用途 |
            label, typ, initial = cells[1], cells[2].strip("`"), cells[3]
            labels.setdefault(key, label)
            all_keys.setdefault(key, typ)   # §3に無い拡張KEYもここで拾う
            class_hints[cur_class][key] = {"default_visible": initial == "表示"}

    return all_keys, labels, class_hints


def emit(all_keys, labels, class_hints) -> str:
    out = []
    w = out.append
    w('"""LogSeeker標準タクソノミー（docs/taxonomy.md から自動生成。手で編集しない）。')
    w("")
    w("生成: python3 backend/tools/gen_taxonomy.py docs/taxonomy.md backend/app/taxonomy_master.py")
    w("")
    w("v12 §4.1.1 の「受信フィールド」= payload内のKEYのうち ALL_KEYS と完全一致するものだけ。")
    w("ALL_KEYS はClassに依存しない全体集合であり、Class VALUEはこの一覧を制限しない")
    w("（taxonomy.md §3）。CLASS_HINTS は日本語表示名・初期表示の手がかりに過ぎず、")
    w("ここに無いKEYを選べなくする用途には使わない。")
    w('"""')
    w("")
    w(f"# 全Taxonomy KEY（{len(all_keys)}件）: KEY -> 型")
    w("ALL_KEYS: dict[str, str] = {")
    for k in sorted(all_keys):
        w(f"    {k!r}: {all_keys[k]!r},")
    w("}")
    w("")
    w(f"# 日本語表示名（{len(labels)}件）。未定義のKEYは画面でKEY名をそのまま表示する。")
    w("LABELS: dict[str, str] = {")
    for k in sorted(labels):
        w(f"    {k!r}: {labels[k]!r},")
    w("}")
    w("")
    w("# Class VALUE別の初期表示ヒント（taxonomy.md §6。既定列の算出にのみ使う）")
    w("CLASS_HINTS: dict[str, dict[str, dict]] = {")
    for c in sorted(class_hints):
        w(f"    {c!r}: {{")
        for k in sorted(class_hints[c]):
            w(f"        {k!r}: {class_hints[c][k]!r},")
        w("    },")
    w("}")
    w("")
    w("")
    w("# 大文字小文字を無視した照合用の索引: lower(KEY) -> Taxonomy KEY（正規表記）")
    w("_LOWER: dict[str, str] = {k.lower(): k for k in ALL_KEYS}")
    w("")
    w("")
    w("def canonical_key(key: str) -> str | None:")
    w('    """受信KEYに対応するTaxonomy KEY（正規表記）。無ければNone。')
    w("")
    w("    照合は大文字小文字を区別しない。`EventTime` / `EVENTTIME` / `Eventtime` はいずれも")
    w("    Taxonomy KEY `eventtime` として扱う。**受信payloadのKEY名自体は変更しない**")
    w("    （保存時の読み替えではなく、Taxonomyを参照するときだけ lower() で突き合わせる）。")
    w("")
    w("    大文字小文字の差ではなくKEY名そのものが違うものは一致しない:")
    w("      host != hostname / vhost != virtualhost / client != srcipv4 / time != eventtime")
    w('    """')
    w("    return _LOWER.get(key.lower())")
    w("")
    w("")
    w("def is_taxonomy_key(key: str) -> bool:")
    w('    """受信KEYがTaxonomy KEYに一致するか（大文字小文字は区別しない。v12 §4.1.1）。"""')
    w("    return key.lower() in _LOWER")
    w("")
    w("")
    w("def label_of(key: str) -> str | None:")
    w('    """日本語表示名。未定義ならNone（呼び出し側はKEY名をそのまま表示する）。"""')
    w("    c = canonical_key(key)")
    w("    return LABELS.get(c) if c else None")
    w("")
    w("")
    w("def default_columns(class_value: str | None) -> list[str]:")
    w('    """そのClassの既定表示列。taxonomy.md §6で「初期表示=表示」のKEY。')
    w("    §6に参考例が無いClass VALUEでも動く必要があるため、無ければ汎用の最小セットを返す。")
    w('    """')
    w("    hints = CLASS_HINTS.get(class_value or '')")
    w("    if hints:")
    w("        return [k for k, v in hints.items() if v['default_visible']]")
    w("    generic = ['class', 'eventtime', 'hostname', 'description']")
    w("    return [k for k in generic if k in ALL_KEYS]")
    return "\n".join(out) + "\n"


def main() -> None:
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, encoding="utf-8") as f:
        md = f.read()
    all_keys, labels, class_hints = parse(md)
    with open(dst, "w", encoding="utf-8") as f:
        f.write(emit(all_keys, labels, class_hints))
    print(f"ALL_KEYS={len(all_keys)} LABELS={len(labels)} CLASSES={len(class_hints)}")
    for c, v in sorted(class_hints.items()):
        vis = sum(1 for x in v.values() if x["default_visible"])
        print(f"  {c:16s} keys={len(v):3d} default_visible={vis}")


if __name__ == "__main__":
    main()
