"""ルールパックの署名ツール（Ed25519。docs/rulepack.md「署名」）。

外部へ配信するルールパックは、配信元で秘密鍵により署名し、各LogSeekerは公開鍵で検証してから
読み込む（rulepack.verify_signature）。同梱パック（rulepacks/builtin.yaml）は署名不要。

    # 鍵の生成（秘密鍵ファイルを作り、公開鍵を表示する。秘密鍵は配信元の手元だけに置く）
    python tools/rulepack_sign.py keygen rulepack-signing.key

    # 署名（<pack>.sig を作る）
    python tools/rulepack_sign.py sign rules.yaml rulepack-signing.key

    # 検証（公開鍵はbase64。複数ならカンマ区切り）
    python tools/rulepack_sign.py verify rules.yaml rules.yaml.sig <公開鍵>

**秘密鍵をこのリポジトリ（公開）にコミットしないこと。** 公開鍵は公開してよい。
"""
import base64
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def keygen(path: str) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    p = Path(path)
    if p.exists():
        sys.exit(f"既に存在します（上書きしません）: {p}")
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(_b64(raw) + "\n")
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print(f"秘密鍵: {p}（権限600。配信元の手元だけに保管）")
    print(f"公開鍵: {_b64(pub)}")


def sign(pack: str, keyfile: str) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(Path(keyfile).read_text().strip()))
    data = Path(pack).read_bytes()
    out = Path(pack + ".sig")
    out.write_text(_b64(key.sign(data)) + "\n")
    print(f"署名しました: {out}")


def verify(pack: str, sigfile: str, pubkeys: str) -> None:
    from app.rulepack import verify_signature

    ok = verify_signature(Path(pack).read_bytes(), Path(sigfile).read_text(), pubkeys.split(","))
    print("OK: 署名は有効です" if ok else "NG: 署名が一致しません")
    sys.exit(0 if ok else 1)


def main() -> None:
    a = sys.argv[1:]
    if len(a) == 2 and a[0] == "keygen":
        keygen(a[1])
    elif len(a) == 3 and a[0] == "sign":
        sign(a[1], a[2])
    elif len(a) == 4 and a[0] == "verify":
        verify(a[1], a[2], a[3])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
