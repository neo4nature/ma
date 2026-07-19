"""
KeyManager – MA v0.1 (secp256k1)

F-02: prywatny material trzymamy tylko w vault blobach na dysku
i w RAM keystore w pamieci. Odczyt legacy *.priv.pem gated flaga
MA_ALLOW_LEGACY_PLAINTEXT_KEYS (default OFF).
"""
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


BASE_DIR = Path(__file__).resolve().parent.parent

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

DATA_DIR = _data_dir()
SECRETS_DIR = _secrets_dir()

_priv_legacy = DATA_DIR / "secp256k1_private.pem"
_pub_legacy = DATA_DIR / "secp256k1_public.pem"
PRIV_KEY_FILE = (SECRETS_DIR / "secp256k1_private.pem") if not _priv_legacy.exists() else _priv_legacy
PUB_KEY_FILE = (SECRETS_DIR / "secp256k1_public.pem") if not _pub_legacy.exists() else _pub_legacy


def _chmod_600(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def ensure_keypair_exists() -> None:
    vault_path = vault_path_for(PRIV_KEY_FILE)
    if vault_path.exists() and PUB_KEY_FILE.exists():
        return
    if PRIV_KEY_FILE.exists() and PUB_KEY_FILE.exists():
        # F-02: legacy stan; ostatecznie migracja go usunie
        return

    private_key = ec.generate_private_key(ec.SECP256K1())
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    save_encrypted_private_key(
        vault_path,
        private_key,
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        pub_text=pub_pem.decode("utf-8", errors="ignore"),
    )
    PUB_KEY_FILE.write_bytes(pub_pem)


def _read_priv_via_vault_chain(user_dirs, filenames_priv, filenames_pub) -> bytes | None:
    """RAM keystore -> vault blob -> (opcjonalnie) legacy plaintext PEM."""
    # 1) vault blob w kazdym katalogu, dla kazdej z konwencji nazw
    for d in user_dirs:
        for fn in filenames_priv:
            vault = vault_path_for(d / fn)
            if vault.exists():
                return load_encrypted_priv(vault)
    # 2) legacy plaintext (tylko za flaga)
    if legacy_plaintext_allowed():
        for d in user_dirs:
            for fn in filenames_priv:
                p = d / fn
                if p.exists():
                    return p.read_bytes()
    else:
        for d in user_dirs:
            for fn in filenames_priv:
                p = d / fn
                if p.exists():
                    raise RuntimeError(
                        "F-02: plaintext klucz prywatny na dysku ({}); uruchom migracje "
                        "albo ustaw MA_ALLOW_LEGACY_PLAINTEXT_KEYS=1".format(p)
                    )
    return None


def load_private_key_pem(user: str | None = None) -> bytes:
    """Load private key: RAM keystore -> vault -> legacy plaintext (za flaga)."""
    if user:
        u = str(user).strip()
        if u:
            try:
                from core.ram_keystore import get_wallet_priv_pem
                pem = get_wallet_priv_pem(u)
                if pem:
                    return pem
            except Exception:
                pass

            user_dir = SECRETS_DIR / "keys_wallet"
            legacy_user_dir = DATA_DIR / "keys_wallet"
            dirs = [user_dir, legacy_user_dir]
            names = [f"{u}_priv.pem", f"{u}.secp256k1.priv.pem"]
            pubs = [f"{u}_pub.pem", f"{u}.secp256k1.pub.pem"]
            pem = _read_priv_via_vault_chain(dirs, names, pubs)
            if pem is not None:
                return pem

    ensure_keypair_exists()
    vault_path = vault_path_for(PRIV_KEY_FILE)
    if vault_path.exists():
        return load_encrypted_priv(vault_path)
    if PRIV_KEY_FILE.exists():
        if legacy_plaintext_allowed():
            return PRIV_KEY_FILE.read_bytes()
        raise RuntimeError(
            "F-02: legacy plaintext global key ({}); uruchom migracje albo MA_ALLOW_LEGACY_PLAINTEXT_KEYS=1".format(PRIV_KEY_FILE)
        )
    raise FileNotFoundError("brak globalnego klucza prywatnego (ani vault ani plaintext)")


def load_public_key_pem(user: str | None = None) -> bytes:
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
