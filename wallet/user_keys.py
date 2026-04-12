from __future__ import annotations

import os
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def _resolve_keys_dir(base_dir: str) -> Path:
    """Resolve keys directory for wallet signing keys.

    Prefer MA_SECRETS_DIR, fall back to MA_DATA_DIR, else <base_dir>/data.
    """
    try:
        from core.paths import wallet_keys_dir
        return wallet_keys_dir()
    except Exception:
        base = Path(base_dir)
        data_dir = Path(os.getenv("MA_DATA_DIR") or (base / "data"))
        secrets_dir = Path(os.getenv("MA_SECRETS_DIR") or (data_dir / "secrets"))
        d = secrets_dir / "keys_wallet"
        d.mkdir(parents=True, exist_ok=True)
        return d


def _chmod_600(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def ensure_user_wallet_keypair(user: str, keys_dir: Path) -> Tuple[bytes, bytes]:
    """Create/load a per-user secp256k1 keypair for signing (local prototype)."""
    keys_dir.mkdir(parents=True, exist_ok=True)
    user_safe = user.replace('/', '_').replace('..','_')
    priv_path = keys_dir / f"{user_safe}.secp256k1.priv.pem"
    pub_path  = keys_dir / f"{user_safe}.secp256k1.pub.pem"

    if priv_path.exists() and pub_path.exists():
        return priv_path.read_bytes(), pub_path.read_bytes()

    priv = ec.generate_private_key(ec.SECP256K1())
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    _chmod_600(priv_path)
    return priv_pem, pub_pem


def generate_user_keypair(base_dir: str, username: str) -> Tuple[bytes, bytes]:
    """Generate (or load) the user's secp256k1 keypair.

    Returns (priv_pem, pub_pem). Stored on disk in the resolved keys dir.
    """
    keys_dir = _resolve_keys_dir(base_dir)
    return ensure_user_wallet_keypair(username, keys_dir)


def rotate_user_keypair(base_dir: str, username: str) -> dict:
    """Rotate user's wallet keypair (secp256k1).

    - Archives old key files under data/keys_wallet/archive/<username>/<ts>/
    - Generates a new keypair overwriting <username>.secp256k1.*.pem

    Returns:
      {old_pub_pem: str, new_pub_pem: str, archived_dir: str}
    """
    from datetime import datetime, timezone

    keys_dir = _resolve_keys_dir(base_dir)

    user_safe = str(username).strip()
    if not user_safe:
        raise ValueError("username_required")

    priv_path = keys_dir / f"{user_safe}.secp256k1.priv.pem"
    pub_path  = keys_dir / f"{user_safe}.secp256k1.pub.pem"

    old_pub = pub_path.read_bytes() if pub_path.exists() else b""

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    arch_dir = keys_dir / "archive" / user_safe / ts
    arch_dir.mkdir(parents=True, exist_ok=True)
    if priv_path.exists():
        (arch_dir / priv_path.name).write_bytes(priv_path.read_bytes())
    if pub_path.exists():
        (arch_dir / pub_path.name).write_bytes(pub_path.read_bytes())

    new_priv, new_pub = generate_user_keypair(base_dir, user_safe)
    return {
        "old_pub_pem": old_pub.decode("utf-8", errors="ignore"),
        "new_pub_pem": new_pub.decode("utf-8", errors="ignore"),
        "archived_dir": str(arch_dir),
    }
