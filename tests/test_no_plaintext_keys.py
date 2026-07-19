"""F-02: skaner postępu — plaintext klucze prywatne w repo i runtime.

Kluczowe zasady:
  - Test JEST czerwony dopóki istnieją PEM-y bez szyfrowania (NoEncryption())
    oraz niezaszyfrowane serializacje kluczy prywatnych.
  - @pytest.mark.xfail żeby nie blokował CI, ale wypisywał listę wystąpień.
  - Skan pomija .git, tests/, .venv, __pycache__.

Skanowane wzorce (obejmują wszystkie 7 miejsc z audytu F-02):
  wallet/user_keys.py, wallet/key_manager.py, core/comm_crypto.py,
  core/horizon_signer.py, core/rounds.py, daemon/walletd.py, wallet/horizon_keys.py

Runtime skan: obecność niezaszyfrowanych plików *.pem prywatnych w katalogach
kluczy (heurystyka: nagłówek nie zawiera 'ENCRYPTED').
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", ".venv", "__pycache__", "tests", ".pytest_cache", "node_modules"}

# Wzorce sygnalizujące plaintext klucz prywatny.
PATTERNS = [
    re.compile(r"serialization\.NoEncryption\s*\(\s*\)"),
    re.compile(r"encryption_algorithm\s*=\s*serialization\.NoEncryption"),
    # Bezpośrednie NoEncryption() z aliasu importu.
    re.compile(r"\bNoEncryption\s*\(\s*\)"),
]


def _scan_sources():
    """Return list of (path, line_no, snippet) for plaintext key writes."""
    hits = []
    for root, dirs, files in os.walk(REPO_ROOT):
        # Prune skip dirs in-place.
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if not name.endswith(".py"):
                continue
            p = Path(root) / name
            try:
                lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                continue
            for i, line in enumerate(lines, 1):
                for pat in PATTERNS:
                    if pat.search(line):
                        hits.append(
                            (str(p.relative_to(REPO_ROOT)), i, line.strip())
                        )
                        break
    return hits


def _scan_runtime_pems():
    """Return list of *.pem files with a private key header that is NOT encrypted.

    Heurystyka: BEGIN PRIVATE KEY / BEGIN EC PRIVATE KEY bez 'ENCRYPTED' w
    nagłówku pierwszych ~200 bajtów.
    """
    runtime = REPO_ROOT / "runtime"
    hits = []
    if not runtime.exists():
        return hits
    for p in runtime.rglob("*.pem"):
        try:
            head = p.read_bytes()[:400]
        except Exception:
            continue
        text = head.decode("utf-8", errors="ignore")
        if "PRIVATE KEY" in text and "ENCRYPTED" not in text.split("\n", 1)[0].upper():
            # Prywatny, ale bez oznaczenia ENCRYPTED w nagłówku.
            if "ENCRYPTED PRIVATE KEY" not in text:
                hits.append(str(p.relative_to(REPO_ROOT)))
    return hits


@pytest.mark.xfail(
    strict=False,
    reason="F-02: migracja kluczy czeka na decyzję Neo — licznik postępu",
)
def test_no_plaintext_key_serialization_in_sources():
    hits = _scan_sources()
    # Zawsze wypisz raport dla operatora.
    report = "\n".join(f"  {p}:{n}  {s}" for p, n, s in hits)
    print(
        f"\n[F-02] plaintext key serialization occurrences: {len(hits)}\n{report}"
    )
    assert not hits, f"{len(hits)} plaintext key sites found"


@pytest.mark.xfail(
    strict=False,
    reason="F-02: migracja kluczy czeka na decyzję Neo — licznik postępu (runtime)",
)
def test_no_plaintext_private_pem_in_runtime():
    hits = _scan_runtime_pems()
    report = "\n".join(f"  {p}" for p in hits)
    print(
        f"\n[F-02] unencrypted private PEM files in runtime: {len(hits)}\n{report}"
    )
    assert not hits, f"{len(hits)} unencrypted PEM files in runtime"
