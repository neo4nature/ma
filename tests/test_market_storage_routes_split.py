import importlib
import io
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


def test_market_and_storage_route_split(tmp_path):
    app_mod = _load_app(tmp_path)
    client = app_mod.app.test_client()

    resp = client.post("/register", data={"username": "neo", "password": "pw123"}, follow_redirects=False)
    assert resp.status_code == 302

    resp2 = client.get("/market")
    assert resp2.status_code == 200
    txt = resp2.get_data(as_text=True).lower()
    assert "market" in txt or "compute" in txt

    resp3 = client.get("/storage", follow_redirects=False)
    assert resp3.status_code == 200

    rules = {r.rule for r in app_mod.app.url_map.iter_rules()}
    assert "/market" in rules
    assert "/storage" in rules


def test_market_create_and_storage_upload_route_split(tmp_path):
    app_mod = _load_app(tmp_path)
    client = app_mod.app.test_client()
    resp = client.post("/register", data={"username": "neo", "password": "pw123"}, follow_redirects=False)
    assert resp.status_code == 302

    with client.session_transaction() as sess:
        sess["username"] = "neo"

    resp2 = client.post(
        "/market/create",
        data={
            "title": "Test listing",
            "description": "Listing from split route",
            "price": "3.5",
            "bg_mode": "auto",
        },
        follow_redirects=False,
    )
    assert resp2.status_code == 302
    assert "/market" in resp2.headers["Location"]

    listings = app_mod.list_market_listings(app_mod.BASE_DIR, status=None, limit=50)
    assert any((x.get("title") == "Test listing" and x.get("seller") == "neo") for x in listings)

    data = {
        "chunk_size_mb": "1",
        "file": (io.BytesIO(b"hello ma storage split"), "hello.txt"),
    }
    resp3 = client.post("/storage/upload", data=data, content_type="multipart/form-data")
    assert resp3.status_code == 200
    body = resp3.get_data(as_text=True).lower()
    assert "hello.txt" in body or "chunk" in body
