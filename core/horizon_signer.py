from __future__ import annotations

import os
import base64
import hashlib
from pathlib import Path
from typing import Dict, Any, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def _chmod_600(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def ensure_horizon_master_keypair(keys_dir: Path) -> Tuple[bytes, bytes]:
    """Create or load a single Horizon master Ed25519 keypair (prototype)."""
    keys_dir.mkdir(parents=True, exist_ok=True)
    priv_path = keys_dir / "horizon_master_ed25519_priv.pem"
    pub_path = keys_dir / "horizon_master_ed25519_pub.pem"

    if priv_path.exists() and pub_path.exists():
        return priv_path.read_bytes(), pub_path.read_bytes()

    priv = ed25519.Ed25519PrivateKey.generate()
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


def sign_horizon_receipt(tx: Dict[str, Any], keys_dir: Path) -> Dict[str, str]:
    """Sign a minimal Horizon receipt: sha256(canonical_tx_bytes)."""
    # canonical bytes similar to tx_signer (sort keys, compact)
    import json
    payload = json.dumps(tx, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    tx_hash = hashlib.sha256(payload).hexdigest()

    priv_pem, pub_pem = ensure_horizon_master_keypair(keys_dir)
    priv = serialization.load_pem_private_key(priv_pem, password=None)

    sig = priv.sign(tx_hash.encode("ascii"))
    return {
        "tx_hash": tx_hash,
        "horizon_sig_b64": base64.b64encode(sig).decode("ascii"),
        "horizon_pub_pem": pub_pem.decode("utf-8", errors="ignore"),
    }


def verify_horizon_receipt(tx_hash: str, sig_b64: str, pub_pem: str) -> bool:
    try:
        pub = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
        sig = base64.b64decode(sig_b64.encode("ascii"))
        pub.verify(sig, tx_hash.encode("ascii"))
        return True
    except Exception:
        return False
