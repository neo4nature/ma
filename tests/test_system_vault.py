"""F-02: system_vault — jedyna warstwa zarządzania sekretami na dysku.

Kontrakt (od Liry):
  - żaden priv PEM nie zapisuje sie plaintextem na dysk
  - odszyfrowanie tylko do RAM
  - jedna kontrolowana warstwa (core/system_vault.py)
  - migracja plaintext -> vault + ostatecznie skaner na twardo

Testy tests-first: wolno im byc czerwonymi zanim wprowadzimy implementacje.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# (a) roundtrip save/load na tmp_path
# ---------------------------------------------------------------------------
def test_vault_roundtrip_bytes(tmp_path, monkeypatch):
    monkeypatch.setenv("MA_SECRETS_DIR", str(tmp_path / "secrets"))
    monkeypatch.setenv("MA_VAULT_PASSWORD", "unit-test-pw-1")
    from core import system_vault
    system_vault._reset_cache_for_tests()

    priv_pem = b"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"
    pub_pem = "-----BEGIN PUBLIC KEY-----\nxyz\n-----END PUBLIC KEY-----\n"
    blob_path = tmp_path / "unit_test.vault.json"

    system_vault.save_encrypted_priv_bytes(blob_path, priv_pem, pub_pem)
    assert blob_path.exists()
    # blob to JSON, priv nie moze byc widoczny w plaintext
    text = blob_path.read_text(encoding="utf-8")
    assert "BEGIN PRIVATE KEY" not in text
    data = json.loads(text)
    for k in ("pub", "enc_priv_b64", "salt_b64", "nonce_b64", "kdf_json"):
        assert k in data

    out = system_vault.load_encrypted_priv(blob_path)
    assert out == priv_pem


# ---------------------------------------------------------------------------
# (b) generowanie kluczy nie zostawia *.priv.pem na dysku
# ---------------------------------------------------------------------------
def test_ensure_user_wallet_keypair_leaves_no_plaintext(tmp_path, monkeypatch):
    monkeypatch.setenv("MA_SECRETS_DIR", str(tmp_path / "secrets"))
    monkeypatch.setenv("MA_VAULT_PASSWORD", "unit-test-pw-2")
    # Odswiez modul zeby zlapal env
    for mod in ("core.system_vault", "core.paths", "wallet.user_keys",
                "wallet.key_manager", "wallet.tx_signer"):
        if mod in sys.modules:
            del sys.modules[mod]

    from core.paths import wallet_keys_dir
    from wallet.user_keys import ensure_user_wallet_keypair

    keys_dir = wallet_keys_dir()
    priv_pem, pub_pem = ensure_user_wallet_keypair("alice", keys_dir)
    assert b"BEGIN PRIVATE KEY" in priv_pem
    assert b"BEGIN PUBLIC KEY" in pub_pem

    plaintext_priv = keys_dir / "alice.secp256k1.priv.pem"
    vault_blob = keys_dir / "alice.secp256k1.vault.json"
    pub_path = keys_dir / "alice.secp256k1.pub.pem"

    assert not plaintext_priv.exists(), "plaintext PEM prywatny nie moze istniec"
    assert vault_blob.exists(), "vault blob musi byc"
    assert pub_path.exists(), "pub PEM zostaje plaintextem"


def test_ensure_user_horizon_keypair_leaves_no_plaintext(tmp_path, monkeypatch):
    monkeypatch.setenv("MA_SECRETS_DIR", str(tmp_path / "secrets"))
    monkeypatch.setenv("MA_VAULT_PASSWORD", "unit-test-pw-3")
    for mod in ("core.system_vault", "core.paths", "wallet.horizon_keys"):
        if mod in sys.modules:
            del sys.modules[mod]
    from wallet.horizon_keys import ensure_user_horizon_keypair

    keys_dir = tmp_path / "secrets" / "keys_horizon"
    priv_pem, pub_b64 = ensure_user_horizon_keypair("bob", keys_dir)
    assert b"BEGIN PRIVATE KEY" in priv_pem

    plaintext = keys_dir / "bob_horizon_priv.pem"
    blob = keys_dir / "bob_horizon.vault.json"
    pub = keys_dir / "bob_horizon_pub.b64"
    assert not plaintext.exists()
    assert blob.exists()
    assert pub.exists()


def test_ensure_comm_keypair_leaves_no_plaintext(tmp_path, monkeypatch):
    monkeypatch.setenv("MA_SECRETS_DIR", str(tmp_path / "secrets"))
    monkeypatch.setenv("MA_VAULT_PASSWORD", "unit-test-pw-4")
    for mod in ("core.system_vault", "core.paths", "core.comm_crypto"):
        if mod in sys.modules:
            del sys.modules[mod]
    from core.comm_crypto import ensure_comm_keypair

    keys_dir = tmp_path / "secrets" / "keys_comm"
    kp = ensure_comm_keypair("carol", keys_dir)
    assert kp.public_b64

    plaintext = keys_dir / "carol.x25519.priv"
    blob = keys_dir / "carol.x25519.vault.json"
    pub = keys_dir / "carol.x25519.pub"
    assert not plaintext.exists()
    assert blob.exists()
    assert pub.exists()


def test_ensure_horizon_master_keypair_leaves_no_plaintext(tmp_path, monkeypatch):
    monkeypatch.setenv("MA_SECRETS_DIR", str(tmp_path / "secrets"))
    monkeypatch.setenv("MA_VAULT_PASSWORD", "unit-test-pw-5")
    for mod in ("core.system_vault", "core.paths", "core.horizon_signer"):
        if mod in sys.modules:
            del sys.modules[mod]
    from core.horizon_signer import ensure_horizon_master_keypair

    keys_dir = tmp_path / "keys_horizon_master"
    priv_pem, pub_pem = ensure_horizon_master_keypair(keys_dir)
    assert b"BEGIN PRIVATE KEY" in priv_pem

    plaintext = keys_dir / "horizon_master_ed25519_priv.pem"
    blob = keys_dir / "horizon_master_ed25519.vault.json"
    pub = keys_dir / "horizon_master_ed25519_pub.pem"
    assert not plaintext.exists()
    assert blob.exists()
    assert pub.exists()


# ---------------------------------------------------------------------------
# (c) load_private_key_pem po wygenerowaniu vault-only dziala (sign+verify)
# ---------------------------------------------------------------------------
def test_tx_signer_works_vault_only(tmp_path, monkeypatch):
    monkeypatch.setenv("MA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("MA_SECRETS_DIR", str(tmp_path / "secrets"))
    monkeypatch.setenv("MA_VAULT_PASSWORD", "unit-test-pw-6")
    for mod in ("core.system_vault", "core.paths", "wallet.user_keys",
                "wallet.key_manager", "wallet.tx_signer"):
        if mod in sys.modules:
            del sys.modules[mod]

    from wallet.user_keys import generate_user_keypair
    from wallet.tx_signer import sign_transaction, verify_transaction

    generate_user_keypair(str(tmp_path), "alice")
    tx = {"id": "t", "sender": "alice", "receiver": "bob", "amount": 1.0}
    sig = sign_transaction(tx, "alice")
    assert verify_transaction(tx, sig, "alice") is True


# ---------------------------------------------------------------------------
# (d) migracja: plaintext -> vault, plaintext znika, podpis dziala
# ---------------------------------------------------------------------------
def test_migration_wallet_plaintext_to_vault(tmp_path, monkeypatch):
    monkeypatch.setenv("MA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("MA_SECRETS_DIR", str(tmp_path / "secrets"))
    monkeypatch.setenv("MA_VAULT_PASSWORD", "unit-test-migrate-1")
    for mod in ("core.system_vault", "core.paths"):
        if mod in sys.modules:
            del sys.modules[mod]

    # Recznie tworzymy plaintext (symulacja starego stanu przed migracja)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    keys_dir = tmp_path / "secrets" / "keys_wallet"
    keys_dir.mkdir(parents=True, exist_ok=True)
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
    priv_path = keys_dir / "alice.secp256k1.priv.pem"
    pub_path = keys_dir / "alice.secp256k1.pub.pem"
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)

    # Uruchom migracje --apply
    script = Path(__file__).resolve().parent.parent / "tools" / "migrate_keys_to_vault.py"
    env = os.environ.copy()
    env["MA_SECRETS_DIR"] = str(tmp_path / "secrets")
    env["MA_VAULT_PASSWORD"] = "unit-test-migrate-1"
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    result = subprocess.run(
        [sys.executable, str(script), "--apply"],
        env=env, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, f"migrate failed: {result.stdout}\n{result.stderr}"

    # Plaintext znika, blob jest
    assert not priv_path.exists(), "plaintext priv PEM musi zniknac po migracji"
    blob_path = keys_dir / "alice.secp256k1.vault.json"
    assert blob_path.exists(), "vault blob musi byc"
    assert pub_path.exists(), "pub zostaje"

    # Podpis dziala po migracji
    for mod in ("core.system_vault", "core.paths", "wallet.user_keys",
                "wallet.key_manager", "wallet.tx_signer"):
        if mod in sys.modules:
            del sys.modules[mod]
    from wallet.tx_signer import sign_transaction, verify_transaction
    tx = {"id": "m1", "sender": "alice", "receiver": "bob", "amount": 2.0}
    sig = sign_transaction(tx, "alice")
    assert verify_transaction(tx, sig, "alice") is True


def test_migration_dry_run_touches_nothing(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    keys_dir = tmp_path / "secrets" / "keys_wallet"
    keys_dir.mkdir(parents=True, exist_ok=True)
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
    priv_path = keys_dir / "dryrun.secp256k1.priv.pem"
    pub_path = keys_dir / "dryrun.secp256k1.pub.pem"
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)

    script = Path(__file__).resolve().parent.parent / "tools" / "migrate_keys_to_vault.py"
    env = os.environ.copy()
    env["MA_SECRETS_DIR"] = str(tmp_path / "secrets")
    env["MA_VAULT_PASSWORD"] = "unit-test-migrate-dry"
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    result = subprocess.run(
        [sys.executable, str(script)],  # brak --apply => dry-run
        env=env, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr

    # Nic nie zmienione
    assert priv_path.exists()
    assert not (keys_dir / "dryrun.secp256k1.vault.json").exists()


# ---------------------------------------------------------------------------
# (e) legacy plaintext bez flagi => fail-closed; z flaga => dziala
# ---------------------------------------------------------------------------
def test_legacy_plaintext_read_denied_without_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("MA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("MA_SECRETS_DIR", str(tmp_path / "secrets"))
    monkeypatch.delenv("MA_ALLOW_LEGACY_PLAINTEXT_KEYS", raising=False)
    monkeypatch.setenv("MA_VAULT_PASSWORD", "unit-test-pw-legacy1")
    for mod in ("core.system_vault", "core.paths", "wallet.user_keys",
                "wallet.key_manager", "wallet.tx_signer"):
        if mod in sys.modules:
            del sys.modules[mod]

    # recznie plaintext (bez vaultu)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    keys_dir = tmp_path / "secrets" / "keys_wallet"
    keys_dir.mkdir(parents=True, exist_ok=True)
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
    (keys_dir / "eve.secp256k1.priv.pem").write_bytes(priv_pem)
    (keys_dir / "eve.secp256k1.pub.pem").write_bytes(pub_pem)

    from wallet.key_manager import load_private_key_pem
    with pytest.raises(Exception):
        load_private_key_pem("eve")


def test_legacy_plaintext_read_allowed_with_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("MA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("MA_SECRETS_DIR", str(tmp_path / "secrets"))
    monkeypatch.setenv("MA_ALLOW_LEGACY_PLAINTEXT_KEYS", "1")
    monkeypatch.setenv("MA_VAULT_PASSWORD", "unit-test-pw-legacy2")
    for mod in ("core.system_vault", "core.paths", "wallet.user_keys",
                "wallet.key_manager", "wallet.tx_signer"):
        if mod in sys.modules:
            del sys.modules[mod]

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    keys_dir = tmp_path / "secrets" / "keys_wallet"
    keys_dir.mkdir(parents=True, exist_ok=True)
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
    (keys_dir / "eve.secp256k1.priv.pem").write_bytes(priv_pem)
    (keys_dir / "eve.secp256k1.pub.pem").write_bytes(pub_pem)

    from wallet.key_manager import load_private_key_pem
    pem = load_private_key_pem("eve")
    assert b"BEGIN PRIVATE KEY" in pem
