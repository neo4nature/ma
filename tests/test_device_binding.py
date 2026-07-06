"""Wallet Device Confirmation Bug (2026-07-06).

require_device=1 bez przypisanego fingerprinta w trybie SOFTWARE = konto
zablokowane bez możliwości potwierdzenia urządzenia. Guard w account()
nie pozwala włączyć wymogu bez fingerprinta.
"""

import importlib
import os
import sys


def _load_app(tmp_path):
    os.environ["MA_DATA_DIR"] = str(tmp_path / "data")
    os.environ["MA_SECRETS_DIR"] = str(tmp_path / "secrets")
    os.environ["MA_SIGNER_MODE"] = "SOFTWARE"
    os.environ.pop("MA_WORKER_TICK_TOKEN", None)
    for mod in [
        "app",
        "wallet.key_manager",
        "wallet.tx_signer",
        "wallet.user_keys",
        "core.paths",
    ]:
        if mod in sys.modules:
            del sys.modules[mod]
    import app  # noqa: F401
    return importlib.reload(sys.modules["app"])


def _client(app_mod):
    from core.security import reset_rate_limits

    reset_rate_limits()
    client = app_mod.app.test_client()
    resp = client.post("/register", data={"username": "neo", "password": "pw123"}, follow_redirects=False)
    assert resp.status_code == 302
    with client.session_transaction() as sess:
        sess["username"] = "neo"
    return client


def test_require_device_rejected_without_fingerprint(tmp_path):
    app_mod = _load_app(tmp_path)
    client = _client(app_mod)
    resp = client.post("/account", data={"require_device": "on", "action": "save"})
    assert resp.status_code == 200
    user = app_mod.get_user_by_username(app_mod.BASE_DIR, "neo")
    assert int(user.get("require_device") or 0) == 0
    assert not user.get("device_fingerprint")
    html = resp.get_data(as_text=True)
    assert "Najpierw przypisz urządzenie" in html


def test_login_not_blocked_after_rejected_toggle(tmp_path):
    app_mod = _load_app(tmp_path)
    client = _client(app_mod)
    client.post("/account", data={"require_device": "on", "action": "save"})
    client.get("/logout")
    from core.security import reset_rate_limits

    reset_rate_limits()
    resp = client.post("/login", data={"username": "neo", "password": "pw123"}, follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" not in (resp.headers.get("Location") or "")
