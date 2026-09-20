from __future__ import annotations

import base64
import hashlib
import importlib
import os
import sys
import time
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519


def _load_app(tmp_path):
    os.environ["MA_DATA_DIR"] = str(tmp_path / "data")
    os.environ["MA_SECRETS_DIR"] = str(tmp_path / "secrets")
    os.environ["MA_SIGNER_MODE"] = "SOFTWARE"
    os.environ["MA_DEVICE_PAIR_OWNER"] = "Natalia"
    os.environ["MA_DEVICE_PAIR_CODE"] = "pair-once-2026"
    for mod in [
        "app", "db", "wallet.key_manager", "wallet.tx_signer", "wallet.user_keys",
        "core.paths", "core.system_vault", "core.comm_crypto",
    ]:
        sys.modules.pop(mod, None)
    import app
    app = importlib.reload(app)
    app.create_user(app.BASE_DIR, "Neo", "pw123")
    app.create_user(app.BASE_DIR, "Natalia", "device-only-password")
    return app


def _device():
    signing_private = ec.generate_private_key(ec.SECP256R1())
    signing_der = signing_private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    x_private = x25519.X25519PrivateKey.generate()
    x_public_raw = x_private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return {
        "device_id": str(uuid.uuid4()),
        "signing_private": signing_private,
        "signing_der": signing_der,
        "x_private": x_private,
        "x_public_raw": x_public_raw,
    }


def _pair(client, device):
    return client.post(
        "/comm/device/pair",
        json={
            "pair_code": "pair-once-2026",
            "device_id": device["device_id"],
            "signing_public_key_b64": base64.b64encode(device["signing_der"]).decode("ascii"),
            "signing_fingerprint": hashlib.sha256(device["signing_der"]).hexdigest(),
            "x25519_public_key_b64": base64.b64encode(device["x_public_raw"]).decode("ascii"),
        },
    )


def _signed_envelope(app, device, receiver_public_b64, text="Hello Neo"):
    message_id = str(uuid.uuid4())
    timestamp_ms = int(time.time() * 1000)
    aad = app.expected_aad("Natalia", "Neo", message_id, timestamp_ms)
    receiver_public = x25519.X25519PublicKey.from_public_bytes(
        base64.b64decode(receiver_public_b64)
    )
    ciphertext, nonce, salt = app.encrypt_for_pair(
        device["x_private"], receiver_public, text.encode("utf-8"), aad
    )
    signing_key_id = "sha256:" + hashlib.sha256(device["signing_der"]).hexdigest()
    env = {
        "device_id": device["device_id"],
        "message_id": message_id,
        "timestamp_ms": timestamp_ms,
        "request_nonce": uuid.uuid4().hex,
        "action": app.ACTION_SEND,
        "receiver": "Neo",
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "aad_b64": base64.b64encode(aad).decode("ascii"),
        "v": app.ENVELOPE_VERSION,
        "key_id": signing_key_id,
        "alg": app.ALG,
    }
    env["signature"] = base64.b64encode(
        device["signing_private"].sign(
            app.canonical_envelope_bytes(env), ec.ECDSA(hashes.SHA256())
        )
    ).decode("ascii")
    return env


def test_phone_pair_send_and_desktop_thread_roundtrip(tmp_path):
    app = _load_app(tmp_path)
    client = app.app.test_client()
    device = _device()

    paired = _pair(client, device)
    assert paired.status_code == 201, paired.get_json()
    pair_data = paired.get_json()
    assert pair_data["owner"] == "Natalia"
    assert pair_data["idempotent_replay"] is False
    assert "Neo" in pair_data["recipient_x25519_keys"]

    env = _signed_envelope(app, device, pair_data["recipient_x25519_keys"]["Neo"])
    env["sender"] = "Neo"  # never authoritative
    sent = client.post("/comm/envelope", json=env)
    assert sent.status_code == 201, sent.get_json()
    assert sent.get_json()["sender"] == "Natalia"

    with client.session_transaction() as session:
        session["username"] = "Neo"
    thread = client.get("/comm/thread/Neo__Natalia")
    assert thread.status_code == 200
    assert thread.get_json()["messages"][0]["body"] == "Hello Neo"

    replay = client.post("/comm/envelope", json=env)
    assert replay.status_code == 200
    assert replay.get_json()["idempotent_replay"] is True


def test_pairing_code_is_single_use_but_same_device_retry_is_idempotent(tmp_path):
    app = _load_app(tmp_path)
    client = app.app.test_client()
    first = _device()
    assert _pair(client, first).status_code == 201

    retry = _pair(client, first)
    assert retry.status_code == 200
    assert retry.get_json()["idempotent_replay"] is True

    second = _device()
    refused = _pair(client, second)
    assert refused.status_code == 409
    assert refused.get_json()["error"] == "pair_code_already_used"


def test_wrong_aad_is_rejected_even_with_valid_device_signature(tmp_path):
    app = _load_app(tmp_path)
    client = app.app.test_client()
    device = _device()
    pair_data = _pair(client, device).get_json()
    env = _signed_envelope(app, device, pair_data["recipient_x25519_keys"]["Neo"])
    env["aad_b64"] = base64.b64encode(b"Neo->Lira|wrong").decode("ascii")
    env["signature"] = base64.b64encode(
        device["signing_private"].sign(
            app.canonical_envelope_bytes(env), ec.ECDSA(hashes.SHA256())
        )
    ).decode("ascii")

    response = client.post("/comm/envelope", json=env)
    assert response.status_code == 400
    assert response.get_json()["error"] == "aad_mismatch"


def test_exact_stored_retry_can_be_verified_after_freshness_window(tmp_path):
    app = _load_app(tmp_path)
    client = app.app.test_client()
    device = _device()
    pair_data = _pair(client, device).get_json()
    env = _signed_envelope(app, device, pair_data["recipient_x25519_keys"]["Neo"])
    assert client.post("/comm/envelope", json=env).status_code == 201

    future = int(env["timestamp_ms"]) + app.MAX_CLOCK_SKEW_MS + 1
    try:
        app.verify_ready_envelope(
            env,
            get_device=lambda device_id: app.get_comm_device(app.BASE_DIR, device_id),
            receiver_exists=lambda username: app.get_user_by_username(app.BASE_DIR, username) is not None,
            now_ms=lambda: future,
        )
        assert False, "freshness guard should reject a new stale request"
    except app.MobileCommError as exc:
        assert exc.code == "timestamp_outside_window"

    verified = app.verify_ready_envelope(
        env,
        get_device=lambda device_id: app.get_comm_device(app.BASE_DIR, device_id),
        receiver_exists=lambda username: app.get_user_by_username(app.BASE_DIR, username) is not None,
        now_ms=lambda: future,
        allow_stale=True,
    )
    assert app.message_matches_verified(app.get_message(app.BASE_DIR, env["message_id"]), verified)


def test_revoked_device_cannot_send(tmp_path):
    app = _load_app(tmp_path)
    client = app.app.test_client()
    device = _device()
    pair_data = _pair(client, device).get_json()
    env = _signed_envelope(app, device, pair_data["recipient_x25519_keys"]["Neo"])
    assert app.revoke_comm_device(app.BASE_DIR, device["device_id"]) is True

    response = client.post("/comm/envelope", json=env)
    assert response.status_code == 403
    assert response.get_json()["error"] == "device_revoked"


def test_desktop_reply_is_encrypted_to_phone_device_key(tmp_path):
    app = _load_app(tmp_path)
    client = app.app.test_client()
    device = _device()
    assert _pair(client, device).status_code == 201
    with client.session_transaction() as session:
        session["username"] = "Neo"

    response = client.post(
        "/comm/send", json={"receiver": "Natalia", "body": "Hello Natalia"}
    )
    assert response.status_code == 200, response.get_json()
    row = app.get_message(app.BASE_DIR, response.get_json()["messages"][0]["id"])
    assert row["receiver_device_id"] == device["device_id"]

    neo_public = app.ensure_comm_keypair("Neo", app.Path(app.COMM_KEYS_DIR)).public_key
    plaintext = app.decrypt_for_pair(
        device["x_private"],
        neo_public,
        base64.b64decode(row["ciphertext_b64"]),
        base64.b64decode(row["nonce_b64"]),
        base64.b64decode(row["salt_b64"]),
        base64.b64decode(row["aad_b64"]),
    )
    assert plaintext == b"Hello Natalia"
