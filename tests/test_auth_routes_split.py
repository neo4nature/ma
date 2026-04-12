import importlib
import os
import sys

from db import create_user, get_user_by_username, init_db
from werkzeug.security import check_password_hash


def _load_app(tmp_path):
    os.environ["MA_DATA_DIR"] = str(tmp_path / "data")
    os.environ["MA_SECRETS_DIR"] = str(tmp_path / "secrets")
    os.environ["MA_SIGNER_MODE"] = "SOFTWARE"
    os.environ.pop("MA_WORKER_TICK_TOKEN", None)
    for mod in ["app", "wallet.key_manager", "wallet.tx_signer", "wallet.user_keys", "core.paths"]:
        if mod in sys.modules:
            del sys.modules[mod]
    import app  # noqa: F401
    return importlib.reload(sys.modules["app"])


def test_register_login_logout_route_split(tmp_path):
    app_mod = _load_app(tmp_path)
    init_db(app_mod.BASE_DIR)
    client = app_mod.app.test_client()

    resp = client.post("/register", data={"username": "neo", "password": "pw123"}, follow_redirects=False)
    assert resp.status_code == 302
    row = get_user_by_username(app_mod.BASE_DIR, "neo")
    assert row is not None
    assert check_password_hash(row["password_hash"], "pw123")

    client2 = app_mod.app.test_client()
    resp2 = client2.post("/login", data={"username": "neo", "password": "pw123"}, follow_redirects=False)
    assert resp2.status_code == 302
    assert "/comm" in resp2.headers["Location"]

    resp3 = client2.get("/logout", follow_redirects=False)
    assert resp3.status_code == 302
    assert resp3.headers["Location"].endswith("/")


def test_fid_challenge_and_verify_route_split(tmp_path):
    app_mod = _load_app(tmp_path)
    init_db(app_mod.BASE_DIR)
    create_user(app_mod.BASE_DIR, "neo", "pw123")
    from wallet.user_keys import generate_user_keypair
    generate_user_keypair(app_mod.BASE_DIR, "neo")

    client = app_mod.app.test_client()
    resp = client.post("/fid/challenge", json={"username": "neo"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True
    chal = body["challenge"]
    payload_hash_b64 = body["payload_hash_b64"]

    sig_b64 = app_mod.sign_hash(payload_hash_b64, signer="neo", purpose="FID_LOGIN")
    assert app_mod.verify_hash(payload_hash_b64, sig_b64, signer="neo", purpose="FID_LOGIN") is True
    resp2 = client.post(
        "/fid/verify",
        json={"username": "neo", "challenge_id": chal["id"], "sig_b64": sig_b64},
    )
    assert resp2.status_code == 200
    body2 = resp2.get_json()
    assert body2["ok"] is True
    assert body2["username"] == "neo"
