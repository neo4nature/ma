"""Testy regresyjne dla blokerów bezpieczeństwa z audytu:

F-01: /fid/login_wallet w trybie SOFTWARE = bypass uwierzytelniania.
F-04: /login next= otwarty redirect.

Wzór ładowania appu skopiowany z tests/test_auth_routes_split.py — każdy test
dostaje świeżą instancję z izolowanym MA_DATA_DIR/MA_SECRETS_DIR i wybranym
MA_SIGNER_MODE.
"""

from __future__ import annotations

import importlib
import os
import sys

from db import create_user, init_db


def _load_app(tmp_path, signer_mode: str = "SOFTWARE"):
    os.environ["MA_DATA_DIR"] = str(tmp_path / "data")
    os.environ["MA_SECRETS_DIR"] = str(tmp_path / "secrets")
    os.environ["MA_SIGNER_MODE"] = signer_mode
    os.environ.pop("MA_WORKER_TICK_TOKEN", None)
    for mod in ["app", "wallet.key_manager", "wallet.tx_signer", "wallet.user_keys", "core.paths"]:
        if mod in sys.modules:
            del sys.modules[mod]
    import app  # noqa: F401
    return importlib.reload(sys.modules["app"])


def _prepare_user(app_mod, username="neo", password="pw123"):
    init_db(app_mod.BASE_DIR)
    try:
        create_user(app_mod.BASE_DIR, username, password)
    except Exception:
        pass
    from wallet.user_keys import generate_user_keypair
    try:
        generate_user_keypair(app_mod.BASE_DIR, username)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# F-01: /fid/login_wallet MUSI odmówić w SOFTWARE
# ---------------------------------------------------------------------------

def test_fid_login_wallet_denied_in_software_mode(tmp_path):
    """W trybie SOFTWARE endpoint nie może przyjąć samego usernama — bo
    serwer trzyma klucz i sam by podpisał wyzwanie, co pozwala zalogować się
    jako dowolny użytkownik znający tylko login."""
    app_mod = _load_app(tmp_path, signer_mode="SOFTWARE")
    _prepare_user(app_mod, "neo", "pw123")

    client = app_mod.app.test_client()
    resp = client.post("/fid/login_wallet", json={"username": "neo"})

    # Musi odmówić: 403 z jasnym błędem, brak sesji.
    assert resp.status_code == 403, f"expected 403, got {resp.status_code}: {resp.data!r}"
    body = resp.get_json() or {}
    assert body.get("ok") is False
    assert "error" in body

    # Kluczowe: sesja NIE została ustawiona.
    with client.session_transaction() as sess:
        assert "username" not in sess


def test_fid_login_wallet_allowed_in_firmware_mode(tmp_path, monkeypatch):
    """W trybie FIRMWARE bramka SIGNER_MODE nie blokuje — endpoint dochodzi
    do właściwej ścieżki (może się wywalić dalej na braku firmware, ale
    NIE na 403 od bramki SOFTWARE)."""
    app_mod = _load_app(tmp_path, signer_mode="FIRMWARE")
    _prepare_user(app_mod, "neo", "pw123")

    # Załatwiamy pełny flow firmware: podpis wykonuje lokalny klucz przez
    # monkeypatch sign_hash_via_firmware, sig verify puszcza defense-in-depth.
    def _fake_sign(purpose, payload_hash_b64, sender=None, meta=None):
        sig = app_mod.sign_hash(payload_hash_b64, signer=sender, purpose=purpose)
        return {"sig_b64": sig}

    monkeypatch.setattr(app_mod, "sign_hash_via_firmware", _fake_sign)

    client = app_mod.app.test_client()
    resp = client.post("/fid/login_wallet", json={"username": "neo"})

    # Nie może to być 403 od bramki SIGNER_MODE — bramka ma przepuścić FIRMWARE.
    assert resp.status_code != 403, f"firmware mode was blocked by SOFTWARE gate: {resp.data!r}"


# ---------------------------------------------------------------------------
# F-04: /login next= open redirect
# ---------------------------------------------------------------------------

def _login_with_next(client, next_value: str, username="neo", password="pw123"):
    return client.post(
        f"/login?next={next_value}",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


def test_login_next_absolute_url_is_ignored(tmp_path):
    app_mod = _load_app(tmp_path, signer_mode="SOFTWARE")
    _prepare_user(app_mod, "neo", "pw123")
    client = app_mod.app.test_client()

    resp = _login_with_next(client, "https://evil.tld")
    assert resp.status_code == 302
    loc = resp.headers.get("Location", "")
    assert "evil.tld" not in loc, f"open redirect to {loc}"
    # Fallback musi być względny, same-origin.
    assert loc.startswith("/"), f"expected relative fallback, got {loc}"


def test_login_next_protocol_relative_is_ignored(tmp_path):
    app_mod = _load_app(tmp_path, signer_mode="SOFTWARE")
    _prepare_user(app_mod, "neo", "pw123")
    client = app_mod.app.test_client()

    # //evil.tld — browser potraktowałby to jako https://evil.tld/
    resp = _login_with_next(client, "//evil.tld")
    assert resp.status_code == 302
    loc = resp.headers.get("Location", "")
    assert "evil.tld" not in loc, f"open redirect to {loc}"
    assert loc.startswith("/") and not loc.startswith("//")


def test_login_next_backslash_bypass_is_ignored(tmp_path):
    app_mod = _load_app(tmp_path, signer_mode="SOFTWARE")
    _prepare_user(app_mod, "neo", "pw123")
    client = app_mod.app.test_client()

    # /\evil.tld — przeglądarki normalizują \ do / → efektywnie //evil.tld
    resp = _login_with_next(client, "/\\evil.tld")
    assert resp.status_code == 302
    loc = resp.headers.get("Location", "")
    assert "evil.tld" not in loc, f"open redirect to {loc}"
    # Nie może zaczynać się od /\ ani od //
    assert not loc.startswith("//")
    assert not loc.startswith("/\\")


def test_login_next_relative_path_is_honored(tmp_path):
    app_mod = _load_app(tmp_path, signer_mode="SOFTWARE")
    _prepare_user(app_mod, "neo", "pw123")
    client = app_mod.app.test_client()

    resp = _login_with_next(client, "/market")
    assert resp.status_code == 302
    loc = resp.headers.get("Location", "")
    assert loc.endswith("/market"), f"expected /market redirect, got {loc}"
