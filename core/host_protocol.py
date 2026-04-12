"""
host_protocol.py – minimalny protokół host ↔ wallet (MOCK v0.1)

Cel: mieć stały format pakietu teraz (Python), a później podmienić transport na USB/serial,
nie ruszając logiki w aplikacji.

Wersja: JSON + nagłówek, bez binarnego framingu (na razie).
"""
from __future__ import annotations

import base64
import json
import os
import time
import uuid
from typing import Any, Dict


def encode_sign_request(tx: Dict[str, Any], sender: str, meta: Dict[str, Any] | None = None) -> bytes:
    """Encode a signing request.

    v0.7 upgrade:
    - monotonic counter (replay guard)
    - random nonce
    - request id
    This stays JSON, transport framing is handled elsewhere.
    """
    meta = meta or {}
    nonce = meta.get("nonce")
    if not nonce:
        nonce = os.urandom(16)
    if isinstance(nonce, str):
        # allow callers to pass already-b64'd nonce
        try:
            nonce_b64 = nonce
        except Exception:
            nonce_b64 = base64.b64encode(os.urandom(16)).decode("utf-8")
    else:
        nonce_b64 = base64.b64encode(nonce).decode("utf-8")

    payload = {
        "type": "SIGN_TX",
        "v": 2,
        "ts": time.time(),
        "req_id": meta.get("req_id") or str(uuid.uuid4()),
        "sender": sender,
        "counter": int(meta.get("counter") or 0),
        "nonce_b64": nonce_b64,
        "tx": tx,
        "algo": "secp256k1-ecdsa-der-b64",
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def encode_sign_hash_request(purpose: str, payload_hash_b64: str, sender: str, meta: Dict[str, Any] | None = None) -> bytes:
    """Encode a generic signing request (hash + purpose).

    This is the building block for FID/login/feed/marketplace signing without mixing domains.
    Replay-guard fields are the same as in encode_sign_request().
    """
    meta = meta or {}
    nonce = meta.get("nonce")
    if not nonce:
        nonce = os.urandom(16)
    if isinstance(nonce, str):
        nonce_b64 = nonce
    else:
        nonce_b64 = base64.b64encode(nonce).decode("utf-8")

    payload = {
        "type": "SIGN",
        "v": 2,
        "ts": time.time(),
        "req_id": meta.get("req_id") or str(uuid.uuid4()),
        "sender": sender,
        "counter": int(meta.get("counter") or 0),
        "nonce_b64": nonce_b64,
        "purpose": (purpose or "GENERIC").strip().upper(),
        "payload_hash_b64": payload_hash_b64,
        "algo": "secp256k1-ecdsa-der-b64",
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def decode_sign_response(raw: bytes) -> Dict[str, Any]:
    obj = json.loads(raw.decode("utf-8"))
    t = obj.get("type")
    if t not in ("SIGN_TX_RESP", "SIGN_RESP"):
        raise ValueError(f"Unexpected response type: {t}")
    return obj


def encode_device_hello_request(meta: Dict[str, Any] | None = None) -> bytes:
    """Ask the wallet daemon/device to identify itself.

    Host uses this to show a stable device fingerprint and verify
    that responses come from the same device (device attestation).
    """
    meta = meta or {}
    payload = {
        "type": "DEVICE_HELLO",
        "v": 1,
        "ts": time.time(),
        "req_id": meta.get("req_id") or str(uuid.uuid4()),
        "want": ["device_pub", "fingerprint", "attestation"],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def decode_device_hello_response(raw: bytes) -> Dict[str, Any]:
    obj = json.loads(raw.decode("utf-8"))
    if obj.get("type") != "DEVICE_HELLO_RESP":
        raise ValueError(f"Unexpected response type: {obj.get('type')}")
    return obj
