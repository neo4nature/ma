from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


@dataclass(frozen=True)
class CommKeypair:
    private_key: x25519.X25519PrivateKey
    public_key: x25519.X25519PublicKey

    @property
    def public_b64(self) -> str:
        return _b64e(self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ))


def ensure_comm_keypair(user: str, keys_dir: Path) -> CommKeypair:
    """Create/load an X25519 keypair for a given user (local prototype)."""
    keys_dir.mkdir(parents=True, exist_ok=True)
    user_safe = user.replace('/', '_').replace('..','_')
    priv_path = keys_dir / f"{user_safe}.x25519.priv"
    pub_path  = keys_dir / f"{user_safe}.x25519.pub"

    if priv_path.exists() and pub_path.exists():
        priv_raw = _b64d(priv_path.read_text(encoding="utf-8").strip())
        priv = x25519.X25519PrivateKey.from_private_bytes(priv_raw)
        pub_raw = _b64d(pub_path.read_text(encoding="utf-8").strip())
        pub = x25519.X25519PublicKey.from_public_bytes(pub_raw)
        return CommKeypair(priv, pub)

    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    priv_path.write_text(_b64e(priv_raw), encoding="utf-8")
    pub_path.write_text(_b64e(pub_raw), encoding="utf-8")
    try:
        os.chmod(priv_path, 0o600)
    except Exception:
        pass
    return CommKeypair(priv, pub)


def _derive_aes_key(shared_secret: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"MA-COMM-E2E-v0",
    ).derive(shared_secret)


def encrypt_for_pair(sender_priv: x25519.X25519PrivateKey,
                     receiver_pub: x25519.X25519PublicKey,
                     plaintext: bytes,
                     aad: bytes) -> Tuple[bytes, bytes, bytes]:
    """Returns (ciphertext, nonce, salt)."""
    shared = sender_priv.exchange(receiver_pub)
    salt = os.urandom(16)
    key = _derive_aes_key(shared, salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return ct, nonce, salt


def decrypt_for_pair(receiver_priv: x25519.X25519PrivateKey,
                     sender_pub: x25519.X25519PublicKey,
                     ciphertext: bytes,
                     nonce: bytes,
                     salt: bytes,
                     aad: bytes) -> bytes:
    shared = receiver_priv.exchange(sender_pub)
    key = _derive_aes_key(shared, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)
