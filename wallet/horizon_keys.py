from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def _chmod_600(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def ensure_user_horizon_keypair(username: str, key_dir: Path) -> Tuple[bytes, str]:
    """
    Prototype: per-user Horizon signing key (Ed25519).

    Returns: (private_pem_bytes, public_b64)
    Private key is stored locally with 0600 permissions.
    """
    key_dir.mkdir(parents=True, exist_ok=True)
    uname = "".join(ch for ch in username if ch.isalnum() or ch in ("-","_")).strip() or "user"

    priv_path = key_dir / f"{uname}_horizon_priv.pem"
    pub_path  = key_dir / f"{uname}_horizon_pub.b64"

    if priv_path.exists() and pub_path.exists():
        try:
            return priv_path.read_bytes(), pub_path.read_text(encoding="utf-8").strip()
        except Exception:
            pass

    priv = ed25519.Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(pub).decode("utf-8")

    priv_path.write_bytes(priv_pem)
    pub_path.write_text(pub_b64, encoding="utf-8")
    _chmod_600(priv_path)

    return priv_pem, pub_b64
