"""F-02: jedyna kontrolowana warstwa zapisu prywatnych sekretow na dysk.

Kontrakt:
  - zaden priv PEM/raw nie trafia na dysk plaintextem
  - odszyfrowanie wraca do RAM wolajacego (nigdy do pliku)
  - pub zostaje plaintextem (nie sekret)

API:
  get_system_vault_password() -> str
      Zwraca haslo systemowego vaultu. Priorytet env MA_VAULT_PASSWORD,
      inaczej plik <MA_SECRETS_DIR>/vault_password (dev-friendly, chmod 600).

  save_encrypted_priv_bytes(path, priv_bytes, pub_text, password=None)
      Serializuje VaultBlob do JSON pod `path` (chmod 600).

  save_encrypted_private_key(path, private_key, *, encoding, format, pub_text,
                              password=None)
      Wygodny wariant: serializuje `private_key` w RAM (bez NoEncryption w
      punkcie wywolania), pakuje do vaultu. Uzywany zamiast plaintext PEM.

  load_encrypted_priv(path, password=None) -> bytes
      Odczyt + decrypt, zwraca priv bytes w RAM.

  vault_path_for(priv_path) -> Path
      Konwencja nazwy pliku vault dla danej sciezki plaintext.
"""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization

from core.key_vault import VaultBlob, encrypt_private, decrypt_private


_CACHED_PASSWORD: Optional[str] = None


def _reset_cache_for_tests() -> None:
    # F-02: uzywane tylko w testach jednostkowych
    global _CACHED_PASSWORD
    _CACHED_PASSWORD = None


def _secrets_root() -> Path:
    # Import tutaj by uniknac cyklu przy imporcie modulow
    from core.paths import secrets_dir
    return secrets_dir()


def get_system_vault_password() -> str:
    global _CACHED_PASSWORD
    if _CACHED_PASSWORD:
        return _CACHED_PASSWORD

    env = os.getenv("MA_VAULT_PASSWORD")
    if env:
        _CACHED_PASSWORD = env
        return env

    root = _secrets_root()
    root.mkdir(parents=True, exist_ok=True)
    path = root / "vault_password"
    if path.exists():
        pw = path.read_text(encoding="utf-8").strip()
        if pw:
            _CACHED_PASSWORD = pw
            return pw

    pw = secrets.token_urlsafe(32)
    path.write_text(pw, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    _CACHED_PASSWORD = pw
    return pw


def vault_path_for(priv_path: Path) -> Path:
    """Zwroc konwencjonalna sciezke .vault.json dla pliku klucza prywatnego.

    Przyklady:
        alice.secp256k1.priv.pem   -> alice.secp256k1.vault.json
        bob_horizon_priv.pem       -> bob_horizon.vault.json
        carol.x25519.priv          -> carol.x25519.vault.json
    """
    name = priv_path.name
    stem = name
    for suffix in (".priv.pem", "_priv.pem", ".priv"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    else:
        # jesli nic z tego nie pasuje, zrzuc .pem
        if stem.endswith(".pem"):
            stem = stem[: -4]
    return priv_path.parent / f"{stem}.vault.json"


def save_encrypted_priv_bytes(
    path: Path,
    priv_bytes: bytes,
    pub_text: str,
    password: Optional[str] = None,
) -> None:
    """Szyfruj priv_bytes i zapisz VaultBlob jako JSON pod `path` (chmod 600)."""
    pw = password or get_system_vault_password()
    blob = encrypt_private(pw, priv_bytes, pub_text)
    payload = {
        "pub": blob.pub,
        "enc_priv_b64": blob.enc_priv_b64,
        "salt_b64": blob.salt_b64,
        "nonce_b64": blob.nonce_b64,
        "kdf_json": blob.kdf_json,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def _serialize_priv_to_ram(private_key, encoding, format) -> bytes:
    # F-02: jedyne miejsce w kodzie prod gdzie priv trafia do bufora bez hasla;
    # bufor istnieje wylacznie w RAM tego procesu i od razu trafia do AES-GCM.
    return private_key.private_bytes(
        encoding=encoding,
        format=format,
        encryption_algorithm=serialization.NoEncryption(),
    )


def save_encrypted_private_key(
    path: Path,
    private_key,
    *,
    encoding,
    format,
    pub_text: str,
    password: Optional[str] = None,
) -> None:
    """Serializuj `private_key` w RAM i zapisz jako vault blob.

    Serializacja odbywa sie tutaj (nie u wolajacego), zeby zaden modul
    produkcyjny nie musial pisac NoEncryption() w swoim kodzie.
    """
    priv_bytes = _serialize_priv_to_ram(private_key, encoding, format)
    save_encrypted_priv_bytes(path, priv_bytes, pub_text, password=password)


def save_encrypted_x25519_raw(
    path: Path,
    private_key,
    pub_text: str,
    password: Optional[str] = None,
) -> None:
    """Dedykowany helper dla X25519 (raw 32B). Zwraca None."""
    priv_raw = _serialize_priv_to_ram(
        private_key,
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
    )
    save_encrypted_priv_bytes(path, priv_raw, pub_text, password=password)


def load_encrypted_priv(path: Path, password: Optional[str] = None) -> bytes:
    pw = password or get_system_vault_password()
    data = json.loads(path.read_text(encoding="utf-8"))
    blob = VaultBlob(
        pub=str(data.get("pub") or ""),
        enc_priv_b64=str(data.get("enc_priv_b64") or ""),
        salt_b64=str(data.get("salt_b64") or ""),
        nonce_b64=str(data.get("nonce_b64") or ""),
        kdf_json=str(data.get("kdf_json") or "{}"),
    )
    return decrypt_private(pw, blob)


def legacy_plaintext_allowed() -> bool:
    return (os.getenv("MA_ALLOW_LEGACY_PLAINTEXT_KEYS") or "").strip() in ("1", "true", "yes")
