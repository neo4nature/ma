"""F-05: publiczne endpointy bez auth — muszą wymagać zalogowania.

Endpoints skanowane:
  GET /api/pool/status         (routes/market_storage.py)
  GET /api/chain/events        (routes/system.py)
  GET /api/blob/chunk/<sha>    (routes/market_storage.py)
  GET /storage/chunk/<sha>     (routes/market_storage.py)

Test korzysta z tego samego wzorca _load_app co inne split-testy — świeży
runtime pod tmp_path, brak wpływu na inne testy.
"""
from __future__ import annotations

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


PROTECTED_GET_ENDPOINTS = [
    "/api/pool/status",
    "/api/chain/events",
    "/api/blob/chunk/deadbeef",
    "/storage/chunk/deadbeef",
]


def _is_unauthorized(status: int) -> bool:
    # require_login uses redirect (302) to login; some deployments may return 401/403.
    return status in (301, 302, 303, 307, 308, 401, 403)


def test_public_endpoints_require_login_when_anonymous(tmp_path):
    app_mod = _load_app(tmp_path)
    client = app_mod.app.test_client()
    for path in PROTECTED_GET_ENDPOINTS:
        resp = client.get(path, follow_redirects=False)
        assert _is_unauthorized(resp.status_code), (
            f"{path} anonymous should be blocked, got {resp.status_code}"
        )


def test_public_endpoints_work_with_session(tmp_path):
    app_mod = _load_app(tmp_path)
    client = app_mod.app.test_client()
    # Register + login (session cookie set by /register).
    resp = client.post(
        "/register", data={"username": "neo", "password": "pw123"}, follow_redirects=False
    )
    assert resp.status_code == 302
    with client.session_transaction() as sess:
        sess["username"] = "neo"

    # pool/status -> 200 JSON ok
    r1 = client.get("/api/pool/status")
    assert r1.status_code == 200
    assert r1.is_json and r1.get_json().get("ok") is True

    # chain/events -> 200 (bundle JSON) or 400 bad_params for defaults? we pass ok defaults.
    r2 = client.get("/api/chain/events")
    assert r2.status_code == 200

    # storage chunk missing -> 404 (nie 302 na login) — kluczowe: auth przechodzi.
    r3 = client.get("/api/blob/chunk/deadbeef", follow_redirects=False)
    assert r3.status_code in (404,), f"expected 404 after auth, got {r3.status_code}"
    r4 = client.get("/storage/chunk/deadbeef", follow_redirects=False)
    assert r4.status_code in (404,), f"expected 404 after auth, got {r4.status_code}"
