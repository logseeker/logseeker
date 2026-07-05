"""将来の拡張ポイント（今は枠だけ）。
ローカルLLM（自宅サーバの Ollama / Gemma 等）にログを渡して解析させる想定。
ログを外部に出さずローカル解析できる構成を将来の売りにする。
本実装では呼び出さない。"""
from typing import Any


def analyze_events(events: list[dict[str, Any]]) -> str | None:
    """（未実装）ローカルLLMにイベントを渡して所見コメントを得る空関数。"""
    raise NotImplementedError("AI analysis is a future extension point; not implemented.")
