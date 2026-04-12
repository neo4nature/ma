import importlib
import os
import sys


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


def test_feed_and_timeline_route_split(tmp_path):
    app_mod = _load_app(tmp_path)
    client = app_mod.app.test_client()

    resp = client.post("/register", data={"username": "neo", "password": "pw123"}, follow_redirects=False)
    assert resp.status_code == 302

    resp2 = client.get("/feed")
    assert resp2.status_code == 200
    assert "feed" in resp2.get_data(as_text=True).lower()

    client2 = app_mod.app.test_client()
    resp3 = client2.get("/timeline", follow_redirects=False)
    assert resp3.status_code in (301, 302)

    rules = {r.rule for r in app_mod.app.url_map.iter_rules()}
    assert "/timeline" in rules


def test_feed_create_route_split_persists_signed_post(tmp_path):
    app_mod = _load_app(tmp_path)
    client = app_mod.app.test_client()
    resp = client.post("/register", data={"username": "neo", "password": "pw123"}, follow_redirects=False)
    assert resp.status_code == 302

    with client.session_transaction() as sess:
        sess["username"] = "neo"

    resp2 = client.post(
        "/feed/create",
        data={
            "community": "ma",
            "text": "Hello from split route",
            "mode": "21",
            "palette": "neo",
            "theme": "dark",
        },
        follow_redirects=False,
    )
    assert resp2.status_code == 302
    assert "/feed" in resp2.headers["Location"]

    posts = app_mod.load_posts()
    assert isinstance(posts, list)
    assert len(posts) >= 1
    first = posts[0]
    assert first["author"] == "neo"
    assert first["text"] == "Hello from split route"
    assert first["purpose"] == "FID_POST"
    assert first["signature_b64"]
    assert app_mod.verify_hash(first["manifest_hash_b64"], first["signature_b64"], "neo", purpose="FID_POST") is True
