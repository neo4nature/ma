#!/usr/bin/env python3
"""F-02: migracja plaintext kluczy prywatnych do vault blobow.

Uzycie:
    python3 tools/migrate_keys_to_vault.py            # dry-run (default)
    python3 tools/migrate_keys_to_vault.py --apply    # faktyczna migracja

Dla kazdego pliku *.priv.pem / *_priv.pem / *.priv pod MA_SECRETS_DIR:
  1. wczytaj priv + odpowiadajacy pub
  2. zaszyfruj (encrypt_private) -> zapisz .vault.json
  3. ROUNDTRIP: decrypt + podpisz testowy hash + zweryfikuj pubem
  4. dopiero po sukcesie: os.remove(plaintext)

Kazdy fail -> plaintext zostaje, koniec kodem !=0.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import sys
from pathlib import Path
from typing import Optional, Tuple

# Zapewnij mozliwosc importu core.* / wallet.*
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
from cryptography.exceptions import InvalidSignature

from core.paths import secrets_dir
from core.system_vault import (
    save_encrypted_priv_bytes,
    load_encrypted_priv,
    vault_path_for,
)


# ---------------------------------------------------------------------------
# Wykrywanie pary pub dla danego priv
# ---------------------------------------------------------------------------
def _find_pub_for(priv_path: Path) -> Optional[Path]:
    name = priv_path.name
    # secp256k1: X.secp256k1.priv.pem  -> X.secp256k1.pub.pem
    if name.endswith(".secp256k1.priv.pem"):
        stem = name[: -len(".priv.pem")]
        cand = priv_path.parent / f"{stem}.pub.pem"
        if cand.exists():
            return cand
    # horizon: X_horizon_priv.pem -> X_horizon_pub.b64
    if name.endswith("_horizon_priv.pem"):
        stem = name[: -len("_priv.pem")]
        cand = priv_path.parent / f"{stem}_pub.b64"
        if cand.exists():
            return cand
    # horizon master
    if name == "horizon_master_ed25519_priv.pem":
        cand = priv_path.parent / "horizon_master_ed25519_pub.pem"
        if cand.exists():
            return cand
    # device
    if name == "device_ed25519_priv.pem":
        cand = priv_path.parent / "device_ed25519_pub.pem"
        if cand.exists():
            return cand
    # comm: X.x25519.priv -> X.x25519.pub
    if name.endswith(".x25519.priv"):
        cand = priv_path.parent / (name[: -len(".priv")] + ".pub")
        if cand.exists():
            return cand
    # fallback: guess ".pub.pem" / ".pub"
    for ext_priv, ext_pub in (
        (".priv.pem", ".pub.pem"),
        ("_priv.pem", "_pub.pem"),
        (".priv", ".pub"),
    ):
        if name.endswith(ext_priv):
            cand = priv_path.parent / (name[: -len(ext_priv)] + ext_pub)
            if cand.exists():
                return cand
    return None


def _pub_text(pub_path: Path) -> str:
    return pub_path.read_text(encoding="utf-8", errors="replace") if pub_path.suffix in (".b64",) \
        else pub_path.read_bytes().decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Roundtrip: podpis testowy + weryfikacja pubem
# ---------------------------------------------------------------------------
def _roundtrip_ok(priv_bytes: bytes, pub_path: Path, is_raw_x25519: bool) -> Tuple[bool, str]:
    try:
        if is_raw_x25519:
            # X25519 nie ma sign/verify; weryfikacja: derive public i porownaj z pub
            priv = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
            derived_pub = priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            stored_pub_b64 = pub_path.read_text(encoding="utf-8").strip()
            stored_pub = base64.b64decode(stored_pub_b64.encode("ascii"))
            if derived_pub != stored_pub:
                return False, "x25519 pub mismatch"
            return True, "ok"

        # PEM priv (Ed25519 lub EC secp256k1)
        priv = serialization.load_pem_private_key(priv_bytes, password=None)
        payload = b"F-02 migration roundtrip"
        digest = hashlib.sha256(payload).digest()

        if isinstance(priv, ed25519.Ed25519PrivateKey):
            sig = priv.sign(payload)
            # public: PEM albo b64
            if pub_path.suffix == ".b64":
                pub_raw = base64.b64decode(pub_path.read_text(encoding="utf-8").strip().encode("ascii"))
                pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)
            else:
                pub = serialization.load_pem_public_key(pub_path.read_bytes())
            try:
                pub.verify(sig, payload)
                return True, "ok"
            except InvalidSignature:
                return False, "ed25519 verify failed"

        # EC secp256k1
        try:
            from cryptography.hazmat.primitives import hashes
            sig = priv.sign(digest, ec.ECDSA(hashes.SHA256()))
            pub = serialization.load_pem_public_key(pub_path.read_bytes())
            pub.verify(sig, digest, ec.ECDSA(hashes.SHA256()))
            return True, "ok"
        except InvalidSignature:
            return False, "ec verify failed"

    except Exception as e:
        return False, f"roundtrip exception: {e.__class__.__name__}: {e}"


# ---------------------------------------------------------------------------
# Wykrycie plaintext plikow do migracji
# ---------------------------------------------------------------------------
def _discover_plaintext_privs(root: Path):
    if not root.exists():
        return []
    hits = []
    for pattern in ("*.priv.pem", "*_priv.pem", "*.x25519.priv"):
        for p in root.rglob(pattern):
            if not p.is_file():
                continue
            # pomijaj vault jesli w blednej nazwie
            if p.name.endswith(".vault.json"):
                continue
            hits.append(p)
    return sorted(set(hits))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="faktycznie migruj (bez tego = dry-run)")
    ap.add_argument("--secrets-dir", default=None, help="nadpisz MA_SECRETS_DIR")
    args = ap.parse_args()

    root = Path(args.secrets_dir) if args.secrets_dir else secrets_dir()
    print(f"[F-02] MA_SECRETS_DIR = {root}")
    print(f"[F-02] tryb          = {'APPLY' if args.apply else 'DRY-RUN'}")

    files = _discover_plaintext_privs(root)
    if not files:
        print("[F-02] Nic do migracji — nie znaleziono plaintext prywatnych kluczy.")
        return 0

    print(f"[F-02] Znaleziono {len(files)} plikow plaintext prywatnych do migracji:")
    for p in files:
        print(f"   - {p.relative_to(root)}")

    ok = 0
    fail = 0
    skip = 0
    for priv_path in files:
        rel = priv_path.relative_to(root)
        vault = vault_path_for(priv_path)
        if vault.exists():
            print(f"SKIP  {rel}  (vault juz istnieje: {vault.name})")
            skip += 1
            continue

        pub_path = _find_pub_for(priv_path)
        if pub_path is None:
            print(f"FAIL  {rel}  (brak pub dla priv)")
            fail += 1
            continue

        is_raw_x25519 = priv_path.suffix == ".priv" and ".x25519" in priv_path.name

        # priv bytes: dla PEM czytamy jako bytes; dla x25519.priv b64 -> raw
        if is_raw_x25519:
            try:
                priv_bytes = base64.b64decode(priv_path.read_text(encoding="utf-8").strip().encode("ascii"))
            except Exception as e:
                print(f"FAIL  {rel}  (bad b64: {e})")
                fail += 1
                continue
            pub_text = pub_path.read_text(encoding="utf-8").strip()
        else:
            priv_bytes = priv_path.read_bytes()
            pub_text = pub_path.read_text(encoding="utf-8", errors="replace") if pub_path.suffix == ".b64" \
                else pub_path.read_bytes().decode("utf-8", errors="replace")

        if not args.apply:
            print(f"OK    {rel}  (dry-run: zapisalabym {vault.name})")
            ok += 1
            continue

        # zapisz vault blob
        try:
            save_encrypted_priv_bytes(vault, priv_bytes, pub_text)
        except Exception as e:
            print(f"FAIL  {rel}  (zapis vault: {e})")
            fail += 1
            continue

        # roundtrip
        try:
            loaded = load_encrypted_priv(vault)
        except Exception as e:
            print(f"FAIL  {rel}  (odczyt vault: {e})")
            # usun uszkodzony blob
            try:
                vault.unlink()
            except Exception:
                pass
            fail += 1
            continue

        if loaded != priv_bytes:
            print(f"FAIL  {rel}  (roundtrip mismatch)")
            try:
                vault.unlink()
            except Exception:
                pass
            fail += 1
            continue

        rt_ok, rt_reason = _roundtrip_ok(loaded, pub_path, is_raw_x25519)
        if not rt_ok:
            print(f"FAIL  {rel}  ({rt_reason})")
            try:
                vault.unlink()
            except Exception:
                pass
            fail += 1
            continue

        # usun plaintext dopiero po zielonym roundtrip
        try:
            os.remove(priv_path)
        except Exception as e:
            print(f"FAIL  {rel}  (usuniecie plaintext: {e})")
            fail += 1
            continue

        print(f"OK    {rel}  -> {vault.name}")
        ok += 1

    print(f"\n[F-02] podsumowanie: OK={ok}  SKIP={skip}  FAIL={fail}  (tryb {'APPLY' if args.apply else 'DRY-RUN'})")
    return 0 if fail == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
