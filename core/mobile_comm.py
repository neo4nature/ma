"""Authenticated ready-made COMM envelopes from external MA devices.

The Android client owns two independent keys:

* ECDSA P-256 authenticates the device and every request.
* X25519 encrypts COMM messages and is stored as a public key only.

The server never accepts an authoritative sender from the request.  A verified
``device_id`` is mapped to its MA owner (Natalia in the first deployment).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519


PROTOCOL = "MA-DEVICE-COMM-V0"
ACTION_SEND = "send_encrypted_message"
ALG = "ES256"
ENVELOPE_VERSION = 3
MAX_CLOCK_SKEW_MS = 5 * 60 * 1000
MAX_CIPHERTEXT_BYTES = 64 * 1024


class MobileCommError(Exception):
    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code = code
        self.status = status


def _b64d(value: str, error: str) -> bytes:
    try:
        return base64.b64decode(str(value).encode("ascii"), validate=True)
    except Exception as exc:
        raise MobileCommError(error) from exc


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def expected_aad(sender: str, receiver: str, message_id: str, timestamp_ms: int) -> bytes:
    """Canonical mobile AAD.

    MA65's legacy web sender uses ``sender->receiver|msg_id|float_ts``.  The
    mobile v3 envelope preserves that shape but replaces the ambiguous float
    with the exact signed integer milliseconds.
    """
    return f"{sender}->{receiver}|{message_id}|{int(timestamp_ms)}".encode("utf-8")


def canonical_envelope_bytes(env: dict[str, Any]) -> bytes:
    ciphertext = _b64d(env.get("ciphertext_b64", ""), "invalid_ciphertext_b64")
    fields = [
        PROTOCOL,
        f"device_id:{env['device_id']}",
        f"message_id:{env['message_id']}",
        f"timestamp_ms:{int(env['timestamp_ms'])}",
        f"request_nonce:{env['request_nonce']}",
        f"action:{env['action']}",
        f"receiver:{env['receiver']}",
        f"ciphertext_sha256:{sha256_hex(ciphertext)}",
        f"nonce_b64:{env['nonce_b64']}",
        f"salt_b64:{env['salt_b64']}",
        f"aad_b64:{env['aad_b64']}",
        f"v:{int(env['v'])}",
        f"key_id:{env['key_id']}",
        f"alg:{env['alg']}",
    ]
    return ("\n".join(fields) + "\n").encode("utf-8")


@dataclass(frozen=True)
class VerifiedEnvelope:
    device: dict[str, Any]
    env: dict[str, Any]
    ciphertext: bytes
    nonce: bytes
    salt: bytes
    aad: bytes


def parse_pairing_keys(data: dict[str, Any]) -> dict[str, str]:
    try:
        device_id = str(uuid.UUID(str(data.get("device_id") or "")))
    except Exception as exc:
        raise MobileCommError("invalid_device_id") from exc

    signing_der = _b64d(data.get("signing_public_key_b64", ""), "invalid_signing_public_key")
    try:
        signing_key = serialization.load_der_public_key(signing_der)
    except Exception as exc:
        raise MobileCommError("invalid_signing_public_key") from exc
    if not isinstance(signing_key, ec.EllipticCurvePublicKey) or not isinstance(
        signing_key.curve, ec.SECP256R1
    ):
        raise MobileCommError("unsupported_signing_public_key")

    signing_fingerprint = sha256_hex(signing_der)
    supplied_fingerprint = str(data.get("signing_fingerprint") or "").lower()
    if not secrets.compare_digest(signing_fingerprint, supplied_fingerprint):
        raise MobileCommError("signing_fingerprint_mismatch")

    x25519_raw = _b64d(data.get("x25519_public_key_b64", ""), "invalid_x25519_public_key")
    if len(x25519_raw) != 32:
        raise MobileCommError("invalid_x25519_public_key")
    try:
        x25519.X25519PublicKey.from_public_bytes(x25519_raw)
    except Exception as exc:
        raise MobileCommError("invalid_x25519_public_key") from exc

    return {
        "device_id": device_id,
        "signing_pub_der_b64": base64.b64encode(signing_der).decode("ascii"),
        "signing_fingerprint": signing_fingerprint,
        "signing_key_id": f"sha256:{signing_fingerprint}",
        "x25519_public_b64": base64.b64encode(x25519_raw).decode("ascii"),
        "x25519_fingerprint": sha256_hex(x25519_raw),
    }


def pair_device(
    data: dict[str, Any],
    *,
    owner_username: str,
    expected_pair_code: str,
    user_exists: Callable[[str], bool],
    get_device: Callable[[str], dict[str, Any] | None],
    store_new_device: Callable[[dict[str, Any], str, str], bool],
) -> dict[str, Any]:
    keys = parse_pairing_keys(data)
    existing = get_device(keys["device_id"])
    if existing:
        comparable = (
            "owner_username",
            "signing_pub_der_b64",
            "signing_fingerprint",
            "signing_key_id",
            "x25519_public_b64",
            "x25519_fingerprint",
        )
        wanted = {**keys, "owner_username": owner_username}
        if all(existing.get(k) == wanted.get(k) for k in comparable):
            if existing.get("revoked_ts") is not None:
                raise MobileCommError("device_revoked", 403)
            return {**existing, "idempotent_replay": True}
        raise MobileCommError("device_id_key_changed", 409)

    if not owner_username or not user_exists(owner_username):
        raise MobileCommError("owner_not_found", 409)
    supplied_code = str(data.get("pair_code") or "")
    if not expected_pair_code or not secrets.compare_digest(expected_pair_code, supplied_code):
        raise MobileCommError("invalid_pair_code", 401)
    code_hash = sha256_hex(f"{owner_username}\0{supplied_code}".encode("utf-8"))
    record: dict[str, Any] = {
        **keys,
        "owner_username": owner_username,
        "created_ts": time.time(),
        "revoked_ts": None,
    }
    if not store_new_device(record, code_hash, owner_username):
        # A simultaneous byte-identical retry may have won the transaction.
        concurrent = get_device(keys["device_id"])
        if concurrent:
            comparable = (
                "owner_username", "signing_pub_der_b64", "signing_fingerprint",
                "signing_key_id", "x25519_public_b64", "x25519_fingerprint",
            )
            if all(concurrent.get(k) == record.get(k) for k in comparable):
                return {**concurrent, "idempotent_replay": True}
        raise MobileCommError("pair_code_already_used", 409)
    return record


def verify_ready_envelope(
    env: dict[str, Any],
    *,
    get_device: Callable[[str], dict[str, Any] | None],
    receiver_exists: Callable[[str], bool],
    now_ms: Callable[[], int] | None = None,
    allow_stale: bool = False,
) -> VerifiedEnvelope:
    now_ms = now_ms or (lambda: int(time.time() * 1000))
    required = {
        "device_id", "message_id", "timestamp_ms", "request_nonce", "action",
        "receiver", "ciphertext_b64", "nonce_b64", "salt_b64", "aad_b64",
        "v", "key_id", "alg", "signature",
    }
    if not required.issubset(env):
        raise MobileCommError("missing_envelope_field")
    try:
        device_id = str(uuid.UUID(str(env["device_id"])))
        message_id = str(uuid.UUID(str(env["message_id"])))
        timestamp_ms = int(env["timestamp_ms"])
    except Exception as exc:
        raise MobileCommError("invalid_envelope_identity") from exc
    if device_id != str(env["device_id"]) or message_id != str(env["message_id"]):
        raise MobileCommError("noncanonical_uuid")
    if not allow_stale and abs(now_ms() - timestamp_ms) > MAX_CLOCK_SKEW_MS:
        raise MobileCommError("timestamp_outside_window", 401)
    if len(str(env["request_nonce"])) < 32:
        raise MobileCommError("request_nonce_too_short")
    if env["action"] != ACTION_SEND:
        raise MobileCommError("wrong_action")
    if env["alg"] != ALG:
        raise MobileCommError("unsupported_algorithm")
    if int(env["v"]) != ENVELOPE_VERSION:
        raise MobileCommError("unsupported_envelope_version")

    device = get_device(device_id)
    if not device:
        raise MobileCommError("unknown_device", 401)
    if device.get("revoked_ts") is not None:
        raise MobileCommError("device_revoked", 403)
    if not secrets.compare_digest(str(device["signing_key_id"]), str(env["key_id"])):
        raise MobileCommError("key_id_mismatch", 401)

    receiver = str(env["receiver"]).strip()
    sender = str(device["owner_username"])
    if not receiver or receiver == sender or not receiver_exists(receiver):
        raise MobileCommError("invalid_receiver")

    ciphertext = _b64d(env["ciphertext_b64"], "invalid_ciphertext_b64")
    nonce = _b64d(env["nonce_b64"], "invalid_nonce_b64")
    salt = _b64d(env["salt_b64"], "invalid_salt_b64")
    aad = _b64d(env["aad_b64"], "invalid_aad_b64")
    if not ciphertext or len(ciphertext) > MAX_CIPHERTEXT_BYTES:
        raise MobileCommError("invalid_ciphertext_size")
    if len(nonce) != 12:
        raise MobileCommError("invalid_nonce_size")
    if len(salt) != 16:
        raise MobileCommError("invalid_salt_size")
    wanted_aad = expected_aad(sender, receiver, message_id, timestamp_ms)
    if not secrets.compare_digest(aad, wanted_aad):
        raise MobileCommError("aad_mismatch")

    try:
        public_der = base64.b64decode(device["signing_pub_der_b64"], validate=True)
        public_key = serialization.load_der_public_key(public_der)
        signature = base64.b64decode(str(env["signature"]).encode("ascii"), validate=True)
        public_key.verify(signature, canonical_envelope_bytes(env), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise MobileCommError("bad_signature", 401) from exc

    return VerifiedEnvelope(device, env, ciphertext, nonce, salt, aad)


def message_matches_verified(existing: dict[str, Any], verified: VerifiedEnvelope) -> bool:
    env = verified.env
    expected = {
        "sender": verified.device["owner_username"],
        "receiver": env["receiver"],
        "ciphertext_b64": env["ciphertext_b64"],
        "nonce_b64": env["nonce_b64"],
        "salt_b64": env["salt_b64"],
        "aad_b64": env["aad_b64"],
        "v": int(env["v"]),
        "sender_device_id": env["device_id"],
    }
    return all(existing.get(k) == v for k, v in expected.items())


def response_for_device(record: dict[str, Any], *, idempotent: bool = False) -> dict[str, Any]:
    return {
        "ok": True,
        "device_id": record["device_id"],
        "owner": record["owner_username"],
        "signing_key_id": record["signing_key_id"],
        "x25519_key_id": f"sha256:{record['x25519_fingerprint']}",
        "idempotent_replay": bool(idempotent or record.get("idempotent_replay")),
    }
