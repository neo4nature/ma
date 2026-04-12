"""
KeyManager – MA v0.1 (secp256k1)

Zamiana HMAC (wspólny sekret) na parę kluczy ECDSA secp256k1:
- private key: tylko lokalnie (plik PEM z uprawnieniami 600)
- public key: może być używany do weryfikacji

Uwaga: to nadal wersja soft/prototyp. Dla produkcji: izolowany signer + szyfrowanie klucza lub secure element.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


BASE_DIR = Path(__file__).resolve().parent.parent

# Unify paths via env vars (MA_DATA_DIR / MA_SECRETS_DIR).
# This reduces "runtime as attack surface" risks because we can keep secrets
# on an encrypted volume, and keep the repo tree clean.
try:
    from core.paths import data_dir as _data_dir, secrets_dir as _secrets_dir
except Exception:
    def _data_dir() -> Path:  # type: ignore
        d = Path(os.getenv("MA_DATA_DIR") or (BASE_DIR / "data"))
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _secrets_dir() -> Path:  # type: ignore
        d = Path(os.getenv("MA_SECRETS_DIR") or (_data_dir() / "secrets"))
        d.mkdir(parents=True, exist_ok=True)
        return d

DATA_DIR = _data_dir()          # legacy location for non-sensitive runtime
SECRETS_DIR = _secrets_dir()    # preferred location for keys

# Prefer secrets dir for global keypair; fall back to legacy data dir if already exists.
_priv_legacy = DATA_DIR / "secp256k1_private.pem"
_pub_legacy = DATA_DIR / "secp256k1_public.pem"
PRIV_KEY_FILE = (SECRETS_DIR / "secp256k1_private.pem") if not _priv_legacy.exists() else _priv_legacy
PUB_KEY_FILE  = (SECRETS_DIR / "secp256k1_public.pem") if not _pub_legacy.exists() else _pub_legacy


def _chmod_600(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except Exception:
        # np. Windows / ograniczenia FS – pomijamy w v0.1
        pass


def ensure_keypair_exists() -> None:
    if PRIV_KEY_FILE.exists() and PUB_KEY_FILE.exists():
        return

    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # v0.1: bez hasła; dodamy później
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    PRIV_KEY_FILE.write_bytes(priv_pem)
    PUB_KEY_FILE.write_bytes(pub_pem)
    _chmod_600(PRIV_KEY_FILE)


def load_private_key_pem(user: str | None = None) -> bytes:
    """Load private key.

    Supports both legacy filenames:
      - <user>_priv.pem
      - <user>.secp256k1.priv.pem
    """
    if user:
        u = str(user).strip()
        if u:
            # Prefer decrypted key from RAM keystore (if present)
            try:
                from core.ram_keystore import get_wallet_priv_pem
                pem = get_wallet_priv_pem(u)
                if pem:
                    return pem
            except Exception:
                pass

            # Prefer secrets dir for per-user keys, but keep legacy support.
            user_dir = SECRETS_DIR / "keys_wallet"
            legacy_user_dir = DATA_DIR / "keys_wallet"
            candidates = [
                user_dir / f"{u}_priv.pem",
                user_dir / f"{u}.secp256k1.priv.pem",
                legacy_user_dir / f"{u}_priv.pem",
                legacy_user_dir / f"{u}.secp256k1.priv.pem",
            ]
            for priv_path in candidates:
                if priv_path.exists():
                    return priv_path.read_bytes()

    ensure_keypair_exists()
    return PRIV_KEY_FILE.read_bytes()

def load_public_key_pem(user: str | None = None) -> bytes:
    """Load public key.

    Supports both legacy filenames:
      - <user>_pub.pem
      - <user>.secp256k1.pub.pem
    """
    if user:
        u = str(user).strip()
        if u:
            user_dir = SECRETS_DIR / "keys_wallet"
            legacy_user_dir = DATA_DIR / "keys_wallet"
            candidates = [
                user_dir / f"{u}_pub.pem",
                user_dir / f"{u}.secp256k1.pub.pem",
                legacy_user_dir / f"{u}_pub.pem",
                legacy_user_dir / f"{u}.secp256k1.pub.pem",
            ]
            for pub_path in candidates:
                if pub_path.exists():
                    return pub_path.read_bytes()

    ensure_keypair_exists()
    return PUB_KEY_FILE.read_bytes()
