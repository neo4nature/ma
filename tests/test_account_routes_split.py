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


_PUB = """-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n-----END PUBLIC KEY-----\n"""


def test_account_and_security_routes_split(tmp_path):
    app_mod = _load_app(tmp_path)
    client = app_mod.app.test_client()

    resp = client.post("/register", data={"username": "neo", "password": "pw123"}, follow_redirects=False)
    assert resp.status_code == 302

    resp2 = client.get("/account")
    assert resp2.status_code == 200

    resp3 = client.get("/account/security")
    assert resp3.status_code == 200

    rules = {r.rule for r in app_mod.app.url_map.iter_rules()}
    assert "/account" in rules
    assert "/account/preferences" in rules
    assert "/account/security" in rules
    assert "/api/account/recovery" in rules
    assert "/api/account/keys/rotate" in rules


def test_account_recovery_and_key_rotation_split(tmp_path):
    app_mod = _load_app(tmp_path)
    client = app_mod.app.test_client()

    resp = client.post("/register", data={"username": "neo", "password": "pw123"}, follow_redirects=False)
    assert resp.status_code == 302

    with client.session_transaction() as sess:
        sess["username"] = "neo"

    get_resp = client.get("/api/account/recovery")
    assert get_resp.status_code == 200
    assert get_resp.get_json()["ok"] is True

    set_resp = client.post("/api/account/recovery", json={"recovery_pub_pem": _PUB})
    assert set_resp.status_code == 200
    assert set_resp.get_json()["has_recovery"] is True

    rotate_resp = client.post("/api/account/keys/rotate")
    assert rotate_resp.status_code == 200
    body = rotate_resp.get_json()
    assert body["ok"] is True
    assert "BEGIN PUBLIC KEY" in (body.get("new_pub_pem") or "")
