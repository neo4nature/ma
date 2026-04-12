"""
TxSigner – MA v0.1 (secp256k1)

Podpisuje transakcje ECDSA na krzywej secp256k1 (standard "bitcoinowy").
Zwraca podpis w base64 (DER).

Ważne: podpisujemy deterministycznie zserializowany JSON:
sort_keys=True + separators=(',', ':').

Uwaga: to jest wersja soft do prototypowania. Dla produkcji: izolowany signer + ochrona klucza.
"""
from __future__ import annotations

import base64
import json
from typing import Dict, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .key_manager import load_private_key_pem, load_public_key_pem


def _canonical_tx_bytes(tx: Dict[str, Any]) -> bytes:
    return json.dumps(tx, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_transaction(tx: Dict[str, Any], signer: str | None = None) -> str:
    priv_pem = load_private_key_pem(signer)
    private_key = serialization.load_pem_private_key(priv_pem, password=None)

    payload = _canonical_tx_bytes(tx)
    signature_der = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature_der).decode("ascii")


def verify_transaction(tx: Dict[str, Any], signature_b64: str, signer: str | None = None) -> bool:
    pub_pem = load_public_key_pem(signer)
    public_key = serialization.load_pem_public_key(pub_pem)

    payload = _canonical_tx_bytes(tx)
    sig = base64.b64decode(signature_b64.encode("ascii"))

    try:
        public_key.verify(sig, payload, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# -------------------------
# Generic signing (hash + purpose)
# -------------------------
def sign_hash(payload_hash_b64: str, signer: str | None = None, purpose: str = "GENERIC") -> str:
    """Sign a precomputed SHA-256 (or other) hash (base64) with a purpose binding.

    We sign canonical bytes: b"MA|SIGN|<PURPOSE>|<HASH_B64>"
    This prevents cross-context signature reuse.
    """
    priv_pem = load_private_key_pem(signer)
    private_key = serialization.load_pem_private_key(priv_pem, password=None)

    purpose_u = (purpose or "GENERIC").strip().upper()
    msg = f"MA|SIGN|{purpose_u}|{payload_hash_b64}".encode("utf-8")
    signature_der = private_key.sign(msg, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature_der).decode("ascii")


def verify_hash(payload_hash_b64: str, signature_b64: str, signer: str | None = None, purpose: str = "GENERIC") -> bool:
    """Verify a signature created by sign_hash()."""
    pub_pem = load_public_key_pem(signer)
    public_key = serialization.load_pem_public_key(pub_pem)

    purpose_u = (purpose or "GENERIC").strip().upper()
    msg = f"MA|SIGN|{purpose_u}|{payload_hash_b64}".encode("utf-8")
    sig = base64.b64decode(signature_b64.encode("ascii"))

    try:
        public_key.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
