from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from core.system_vault import (
    save_encrypted_private_key,
    load_encrypted_priv,
    vault_path_for,
    legacy_plaintext_allowed,
)


def _chmod_600(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def ensure_user_horizon_keypair(username: str, key_dir: Path) -> Tuple[bytes, str]:
    """Prototype: per-user Horizon signing key (Ed25519).

    F-02: priv trzymamy w vault blobie; pub b64 zostaje plaintextem.
    """
    key_dir.mkdir(parents=True, exist_ok=True)
    uname = "".join(ch for ch in username if ch.isalnum() or ch in ("-", "_")).strip() or "user"

    priv_path = key_dir / f"{uname}_horizon_priv.pem"
    pub_path = key_dir / f"{uname}_horizon_pub.b64"
    vault_path = vault_path_for(priv_path)

    if vault_path.exists() and pub_path.exists():
        try:
            priv_pem = load_encrypted_priv(vault_path)
            return priv_pem, pub_path.read_text(encoding="utf-8").strip()
        except Exception:
            pass

    if priv_path.exists() and pub_path.exists():
        if not legacy_plaintext_allowed():
            raise RuntimeError(
                "F-02: plaintext horizon priv na dysku ({}); uruchom migracje".format(priv_path)
            )
        return priv_path.read_bytes(), pub_path.read_text(encoding="utf-8").strip()

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(pub).decode("utf-8")

    save_encrypted_private_key(
        vault_path,
        priv,
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        pub_text=pub_b64,
    )
    pub_path.write_text(pub_b64, encoding="utf-8")

    priv_pem = load_encrypted_priv(vault_path)
    return priv_pem, pub_b64
