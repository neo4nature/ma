from __future__ import annotations

import os
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from core.system_vault import (
    save_encrypted_private_key,
    load_encrypted_priv,
    vault_path_for,
    legacy_plaintext_allowed,
)


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
    user_safe = user.replace('/', '_').replace('..', '_')
    priv_path = keys_dir / f"{user_safe}.secp256k1.priv.pem"
    pub_path = keys_dir / f"{user_safe}.secp256k1.pub.pem"
    vault_path = vault_path_for(priv_path)

    # F-02: preferuj vault; plaintext PEM = legacy, tylko za flaga MA_ALLOW_LEGACY_PLAINTEXT_KEYS
    if vault_path.exists() and pub_path.exists():
        priv_pem = load_encrypted_priv(vault_path)
        return priv_pem, pub_path.read_bytes()
    if priv_path.exists() and pub_path.exists():
        if not legacy_plaintext_allowed():
            raise RuntimeError(
                "F-02: znaleziono plaintext klucz prywatny na dysku "
                f"({priv_path.name}); uruchom tools/migrate_keys_to_vault.py --apply "
                "albo ustaw MA_ALLOW_LEGACY_PLAINTEXT_KEYS=1"
            )
        return priv_path.read_bytes(), pub_path.read_bytes()

    priv = ec.generate_private_key(ec.SECP256K1())
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    save_encrypted_private_key(
        vault_path,
        priv,
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        pub_text=pub_pem.decode("utf-8", errors="ignore"),
    )
    pub_path.write_bytes(pub_pem)
    # priv_pem w RAM dla wolajacego (np. state_service loguje user do vaultu userowym haslem)
    priv_pem = load_encrypted_priv(vault_path)
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
    """
    from datetime import datetime, timezone

    keys_dir = _resolve_keys_dir(base_dir)

    user_safe = str(username).strip()
    if not user_safe:
        raise ValueError("username_required")

    priv_path = keys_dir / f"{user_safe}.secp256k1.priv.pem"
    pub_path = keys_dir / f"{user_safe}.secp256k1.pub.pem"
    vault_path = vault_path_for(priv_path)

    old_pub = pub_path.read_bytes() if pub_path.exists() else b""

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    arch_dir = keys_dir / "archive" / user_safe / ts
    arch_dir.mkdir(parents=True, exist_ok=True)
    # F-02: archiwum vault blob (nie plaintext)
    if vault_path.exists():
        (arch_dir / vault_path.name).write_bytes(vault_path.read_bytes())
        vault_path.unlink()
    if priv_path.exists():
        (arch_dir / priv_path.name).write_bytes(priv_path.read_bytes())
        priv_path.unlink()
    if pub_path.exists():
        (arch_dir / pub_path.name).write_bytes(pub_path.read_bytes())

    new_priv, new_pub = generate_user_keypair(base_dir, user_safe)
    return {
        "old_pub_pem": old_pub.decode("utf-8", errors="ignore"),
        "new_pub_pem": new_pub.decode("utf-8", errors="ignore"),
        "archived_dir": str(arch_dir),
    }
