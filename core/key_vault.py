from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class VaultBlob:
    pub: str
    enc_priv_b64: str
    salt_b64: str
    nonce_b64: str
    kdf_json: str


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _derive_key(password: str, salt: bytes, *, n: int = 2**14, r: int = 8, p: int = 1) -> Tuple[bytes, str]:
    # Scrypt params are a pragmatic default for local prototype.
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    key = kdf.derive(password.encode("utf-8"))
    meta = json.dumps({"kdf": "scrypt", "n": n, "r": r, "p": p}, separators=(",", ":"))
    return key, meta


def encrypt_private(password: str, priv_bytes: bytes, pub_text: str) -> VaultBlob:
    salt = os.urandom(16)
    key, meta = _derive_key(password, salt)
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, priv_bytes, pub_text.encode("utf-8"))
    return VaultBlob(
        pub=pub_text,
        enc_priv_b64=_b64e(ct),
        salt_b64=_b64e(salt),
        nonce_b64=_b64e(nonce),
        kdf_json=meta,
    )


def decrypt_private(password: str, blob: VaultBlob) -> bytes:
    salt = _b64d(blob.salt_b64)
    meta = json.loads(blob.kdf_json)
    if meta.get("kdf") != "scrypt":
        raise ValueError("unsupported_kdf")
    key, _ = _derive_key(password, salt, n=int(meta.get("n", 2**14)), r=int(meta.get("r", 8)), p=int(meta.get("p", 1)))
    aes = AESGCM(key)
    nonce = _b64d(blob.nonce_b64)
    ct = _b64d(blob.enc_priv_b64)
    return aes.decrypt(nonce, ct, blob.pub.encode("utf-8"))
