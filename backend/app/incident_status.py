"""インシデントのステータス遷移可否判定（指示書3章）。

名前ではなく special_type（unassigned/done/reopened/None）で判定することで、
3-3節のステータスマスタのカスタマイズ（名称変更・追加）が行われても、
「未対応/完了/再オープン」という3つの特別ステータスに対する遷移制限の骨格は崩れない。
"""
from .auth import ROLES


def can_transition(from_special: str | None, to_special: str | None, role: str) -> bool:
    """role: User.role の文字列（viewer/editor/sysadmin/admin）。認証OFF時は呼び出し側で "admin" を渡すこと。"""
    if from_special == "unassigned":
        return True  # 未対応 → 任意（権限問わず）
    if to_special == "unassigned":
        return ROLES.get(role, 0) >= ROLES["sysadmin"]  # 他 → 未対応 はsysadmin以上のみ
    if to_special == "done":
        return True  # どの状態からでも完了へは権限問わず可能
    if from_special == "done" and to_special == "reopened":
        return ROLES.get(role, 0) >= ROLES["sysadmin"]  # 完了 → 再オープン はsysadmin以上のみ
    return True  # 調査中/対応中/様子見/報告/再オープンの相互遷移・カスタムステータスは自由
