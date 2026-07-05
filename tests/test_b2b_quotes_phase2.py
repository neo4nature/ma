"""B2B quote Phase 2 tests.

Covers:
- quote-scoped E2E messenger (thread_ref filters by quote_id)
- authorization for messages (third party 403)
- GET /api/quotes list for buyer/seller/third party
- Neo's bulk_only rule (cena < transport => bulk_only)
- price action guard: total_net < transport => total_below_transport
- regression: legacy /comm/send still works with thread_ref = NULL
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
    for mod in ["app", "wallet.key_manager", "wallet.tx_signer", "wallet.user_keys", "core.paths"]:
        if mod in sys.modules:
            del sys.modules[mod]
    import app  # noqa: F401
    mod = importlib.reload(sys.modules["app"])
    try:
        from core.security import reset_rate_limits
        reset_rate_limits()
    except Exception:
        pass
    return mod


def _register_and_login(app_mod, client, username):
    resp = client.post(
        "/register",
        data={"username": username, "password": "pw123"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    with client.session_transaction() as sess:
        sess["username"] = username


def _make_three_clients(app_mod):
    buyer = app_mod.app.test_client()
    seller = app_mod.app.test_client()
    stranger = app_mod.app.test_client()
    _register_and_login(app_mod, buyer, "buyer1")
    _register_and_login(app_mod, seller, "seller1")
    _register_and_login(app_mod, stranger, "stranger1")
    return buyer, seller, stranger


def _create_quote(client, items=None, note=""):
    payload = {
        "seller_username": "seller1",
        "items": items or [{"sku": "BHP-1", "name": "Rekawice", "qty": 3}],
        "note": note,
    }
    resp = client.post("/api/quotes/create", json=payload)
    assert resp.status_code == 201, resp.get_data(as_text=True)
    return resp.get_json()["quote"]["quote_id"]


# --- 1. thread_ref roundtrip + isolation -----------------------------------

def test_quote_message_roundtrip_and_thread_ref_isolation(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller, _ = _make_three_clients(app_mod)

    quote_a = _create_quote(buyer, items=[{"sku": "A", "name": "A", "qty": 1}])
    quote_b = _create_quote(buyer, items=[{"sku": "B", "name": "B", "qty": 1}])

    # buyer -> seller on quote A
    resp = buyer.post(f"/api/quotes/{quote_a}/messages", json={"text": "hej po A"})
    assert resp.status_code == 201, resp.get_data(as_text=True)

    # buyer -> seller on quote B (same pair, different thread)
    resp = buyer.post(f"/api/quotes/{quote_b}/messages", json={"text": "a to jest B"})
    assert resp.status_code == 201

    # seller reads quote A thread — sees only A's message, decrypted
    resp = seller.get(f"/api/quotes/{quote_a}/messages")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["quote_id"] == quote_a
    bodies = [m["body"] for m in data["messages"]]
    assert bodies == ["hej po A"]
    assert data["messages"][0]["sender"] == "buyer1"
    assert data["messages"][0]["receiver"] == "seller1"
    assert data["messages"][0]["thread_ref"] == quote_a

    # seller reads quote B thread — sees only B's message
    resp = seller.get(f"/api/quotes/{quote_b}/messages")
    assert resp.status_code == 200
    bodies = [m["body"] for m in resp.get_json()["messages"]]
    assert bodies == ["a to jest B"]

    # seller can reply on quote A
    resp = seller.post(f"/api/quotes/{quote_a}/messages", json={"text": "odbior potwierdzam"})
    assert resp.status_code == 201
    resp = buyer.get(f"/api/quotes/{quote_a}/messages")
    bodies = [m["body"] for m in resp.get_json()["messages"]]
    assert bodies == ["hej po A", "odbior potwierdzam"]


# --- 2. third user cannot send or read quote messages ----------------------

def test_third_user_forbidden_on_quote_messages(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller, stranger = _make_three_clients(app_mod)
    quote_id = _create_quote(buyer)

    resp = stranger.get(f"/api/quotes/{quote_id}/messages")
    assert resp.status_code == 403

    resp = stranger.post(f"/api/quotes/{quote_id}/messages", json={"text": "hi"})
    assert resp.status_code == 403


def test_quote_messages_auth_required(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, _, _ = _make_three_clients(app_mod)
    quote_id = _create_quote(buyer)

    anon = app_mod.app.test_client()
    resp = anon.get(f"/api/quotes/{quote_id}/messages")
    assert resp.status_code == 401
    resp = anon.post(f"/api/quotes/{quote_id}/messages", json={"text": "hi"})
    assert resp.status_code == 401


def test_quote_message_missing_text_400(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, _, _ = _make_three_clients(app_mod)
    quote_id = _create_quote(buyer)
    resp = buyer.post(f"/api/quotes/{quote_id}/messages", json={"text": "  "})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "missing_text"


# --- 3. GET /api/quotes ----------------------------------------------------

def test_list_quotes_shows_both_sides_not_third(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller, stranger = _make_three_clients(app_mod)

    q1 = _create_quote(buyer, items=[{"sku": "X1", "name": "n", "qty": 1}])
    q2 = _create_quote(buyer, items=[{"sku": "X2", "name": "n", "qty": 1}])

    resp = buyer.get("/api/quotes")
    assert resp.status_code == 200
    quotes = resp.get_json()["quotes"]
    ids = [q["quote_id"] for q in quotes]
    # newest first
    assert ids[0] == q2
    assert q1 in ids
    assert q2 in ids

    resp = seller.get("/api/quotes")
    assert resp.status_code == 200
    ids = [q["quote_id"] for q in resp.get_json()["quotes"]]
    assert q1 in ids and q2 in ids

    resp = stranger.get("/api/quotes")
    assert resp.status_code == 200
    assert resp.get_json()["quotes"] == []


def test_list_quotes_requires_auth(tmp_path):
    app_mod = _load_app(tmp_path)
    anon = app_mod.app.test_client()
    resp = anon.get("/api/quotes")
    assert resp.status_code == 401


# --- 4. Neo's bulk_only rule ----------------------------------------------

def test_create_quote_rejects_below_transport_below_bulk(tmp_path):
    import math
    from services import b2b_quote_service as svc
    app_mod = _load_app(tmp_path)
    buyer, _, _ = _make_three_clients(app_mod)
    # 5 PLN * qty 2 = 10 PLN < 5x transport. Should fail with computed min_qty.
    target = svc.BULK_ONLY_MULTIPLIER * svc.TRANSPORT_COST_PLN
    expected_min_qty = int(math.ceil(target / 5.0))
    resp = buyer.post(
        "/api/quotes/create",
        json={
            "seller_username": "seller1",
            "items": [{"sku": "CHEAP-1", "name": "gwozdz", "qty": 2, "unit_price_net": 5.0}],
        },
    )
    assert resp.status_code == 400
    err = resp.get_json()["error"]
    assert err.startswith("bulk_only:"), err
    assert "CHEAP-1" in err
    assert f"min_qty={expected_min_qty}" in err


def test_create_quote_accepts_bulk_over_threshold(tmp_path):
    import math
    from services import b2b_quote_service as svc
    app_mod = _load_app(tmp_path)
    buyer, _, _ = _make_three_clients(app_mod)
    # exactly min_qty at 5 PLN reaches the 5x-transport target. Should pass.
    target = svc.BULK_ONLY_MULTIPLIER * svc.TRANSPORT_COST_PLN
    min_qty = int(math.ceil(target / 5.0))
    resp = buyer.post(
        "/api/quotes/create",
        json={
            "seller_username": "seller1",
            "items": [{"sku": "CHEAP-1", "name": "gwozdz", "qty": min_qty, "unit_price_net": 5.0}],
        },
    )
    assert resp.status_code == 201, resp.get_data(as_text=True)


def test_create_quote_no_price_skips_bulk_check(tmp_path):
    """Items without unit_price_net are open inquiries — not blocked at create."""
    app_mod = _load_app(tmp_path)
    buyer, _, _ = _make_three_clients(app_mod)
    resp = buyer.post(
        "/api/quotes/create",
        json={
            "seller_username": "seller1",
            "items": [{"sku": "OPEN-1", "name": "cokolwiek", "qty": 1}],
        },
    )
    assert resp.status_code == 201


# --- 5. price action guard -------------------------------------------------

def test_price_below_transport_rejected(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller, _ = _make_three_clients(app_mod)
    quote_id = _create_quote(buyer)

    resp = seller.post(
        f"/api/quotes/{quote_id}/respond",
        json={"action": "price", "total_net": 10.0},
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "total_below_transport"


def test_price_at_or_above_transport_ok(tmp_path):
    from services import b2b_quote_service as svc
    app_mod = _load_app(tmp_path)
    buyer, seller, _ = _make_three_clients(app_mod)
    quote_id = _create_quote(buyer)

    resp = seller.post(
        f"/api/quotes/{quote_id}/respond",
        json={"action": "price", "total_net": svc.TRANSPORT_COST_PLN},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)


# --- 6. regression: legacy comm send still works, thread_ref = NULL --------

def test_legacy_comm_send_still_works(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller, _ = _make_three_clients(app_mod)

    resp = buyer.post(
        "/comm/send",
        json={"receiver": "seller1", "body": "witaj bez quote"},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    msgs = resp.get_json()["messages"]
    assert msgs[0]["body"] == "witaj bez quote"

    # Sanity: the legacy row is stored with thread_ref = NULL and does NOT
    # show up in a quote-scoped thread for the same pair.
    quote_id = _create_quote(buyer)
    resp = buyer.get(f"/api/quotes/{quote_id}/messages")
    assert resp.status_code == 200
    assert resp.get_json()["messages"] == []


# --- 7. route inventory ----------------------------------------------------

def test_phase2_routes_registered(tmp_path):
    app_mod = _load_app(tmp_path)
    rules = {r.rule for r in app_mod.app.url_map.iter_rules()}
    assert "/api/quotes" in rules
    assert "/api/quotes/<quote_id>/messages" in rules
