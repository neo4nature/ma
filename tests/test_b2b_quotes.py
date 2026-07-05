"""B2B quote (zapytanie ofertowe) route + event-chain tests.

Workwear/BHP pilot. OFFLINE_INVOICE only — no settlement.

These tests verify:
- profile upsert + read
- quote create -> SENT + QUOTE_CREATED and QUOTE_SENT on chain
- seller price -> buyer accept -> ACCEPTED + QUOTE_ACCEPTED
- reject path
- authorization (third party denied; buyer cannot price; seller cannot accept)
- invalid transitions rejected (respond on ACCEPTED)
- chain payloads never contain company_name / nip / address / contacts
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path


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


def _read_chain(app_mod, limit=200):
    from core.event_chain import read_events
    log = Path(app_mod.DATA_DIR) / "event_chain" / "event_chain.jsonl"
    state = Path(app_mod.DATA_DIR) / "event_chain" / "event_chain_state.json"
    events, _ = read_events(log_path=log, state_path=state, limit=limit, verify=False)
    return events


# --- routes registered ------------------------------------------------------

def test_b2b_routes_registered(tmp_path):
    app_mod = _load_app(tmp_path)
    rules = {r.rule for r in app_mod.app.url_map.iter_rules()}
    assert "/api/b2b/profile" in rules
    assert "/api/quotes/create" in rules
    assert "/api/quotes/<quote_id>/respond" in rules
    assert "/api/quotes/<quote_id>" in rules


def test_b2b_requires_auth(tmp_path):
    app_mod = _load_app(tmp_path)
    client = app_mod.app.test_client()
    resp = client.get("/api/b2b/profile")
    assert resp.status_code == 401
    resp = client.post("/api/quotes/create", json={})
    assert resp.status_code == 401


# --- profile ---------------------------------------------------------------

def test_profile_upsert_and_read(tmp_path):
    app_mod = _load_app(tmp_path)
    client = app_mod.app.test_client()
    _register_and_login(app_mod, client, "buyer1")

    resp = client.get("/api/b2b/profile")
    assert resp.status_code == 200
    assert resp.get_json()["profile"] is None

    resp = client.post(
        "/api/b2b/profile",
        json={
            "company_name": "Rawpol Sp. z o.o.",
            "nip": "5252525252",
            "billing_address": "ul. Robocza 1, 00-001 Warszawa",
            "contact_email": "biuro@example.pl",
            "contact_phone": "+48 111 222 333",
        },
    )
    assert resp.status_code == 200
    p = resp.get_json()["profile"]
    assert p["company_name"] == "Rawpol Sp. z o.o."
    assert p["nip"] == "5252525252"

    # update overwrites
    resp = client.post(
        "/api/b2b/profile",
        json={"company_name": "Rawpol S.A.", "nip": "5252525252",
              "billing_address": "ul. Nowa 2", "contact_email": "x@y.pl", "contact_phone": ""},
    )
    assert resp.status_code == 200
    resp = client.get("/api/b2b/profile")
    assert resp.get_json()["profile"]["company_name"] == "Rawpol S.A."


# --- happy path: create -> price -> accept ---------------------------------

def _make_buyer_seller(app_mod):
    buyer = app_mod.app.test_client()
    seller = app_mod.app.test_client()
    _register_and_login(app_mod, buyer, "buyer1")
    _register_and_login(app_mod, seller, "seller1")
    return buyer, seller


def test_create_quote_status_sent_and_events(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller = _make_buyer_seller(app_mod)

    resp = buyer.post(
        "/api/quotes/create",
        json={
            "seller_username": "seller1",
            "items": [
                {"sku": "BHP-KAM-001", "name": "Kamizelka odblaskowa", "qty": 20},
                {"listing_id": "L-777", "name": "Buty S3", "qty": 10},
            ],
            "note": "Prosze o wycene do 3 dni.",
        },
    )
    assert resp.status_code == 201, resp.get_data(as_text=True)
    quote = resp.get_json()["quote"]
    assert quote["status"] == "SENT"
    assert quote["payment_method"] == "OFFLINE_INVOICE"
    assert quote["currency"] == "PLN"
    assert quote["total_net"] is None
    assert len(quote["items"]) == 2

    events = _read_chain(app_mod)
    types = [e["type"] for e in events]
    assert "QUOTE_CREATED" in types
    assert "QUOTE_SENT" in types
    created = next(e for e in events if e["type"] == "QUOTE_CREATED")
    assert created["payload"]["quote_id"] == quote["quote_id"]
    assert created["payload"]["payment_method"] == "OFFLINE_INVOICE"


def test_seller_prices_buyer_accepts(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller = _make_buyer_seller(app_mod)

    resp = buyer.post(
        "/api/quotes/create",
        json={
            "seller_username": "seller1",
            "items": [{"sku": "BHP-KAM-001", "name": "Kamizelka", "qty": 5}],
        },
    )
    quote_id = resp.get_json()["quote"]["quote_id"]

    # seller prices
    resp = seller.post(f"/api/quotes/{quote_id}/respond", json={"action": "price", "total_net": 249.90})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    q = resp.get_json()["quote"]
    assert q["status"] == "SENT"
    assert q["total_net"] == 249.90

    # buyer accepts
    resp = buyer.post(f"/api/quotes/{quote_id}/respond", json={"action": "accept"})
    assert resp.status_code == 200
    q = resp.get_json()["quote"]
    assert q["status"] == "ACCEPTED"

    types = [e["type"] for e in _read_chain(app_mod)]
    assert "QUOTE_PRICED" in types
    assert "QUOTE_ACCEPTED" in types


def test_reject_path(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller = _make_buyer_seller(app_mod)
    resp = buyer.post(
        "/api/quotes/create",
        json={"seller_username": "seller1",
              "items": [{"sku": "X", "name": "Rekawice", "qty": 2}]},
    )
    quote_id = resp.get_json()["quote"]["quote_id"]

    resp = buyer.post(f"/api/quotes/{quote_id}/respond", json={"action": "reject"})
    assert resp.status_code == 200
    assert resp.get_json()["quote"]["status"] == "REJECTED"

    types = [e["type"] for e in _read_chain(app_mod)]
    assert "QUOTE_REJECTED" in types


# --- authorization ---------------------------------------------------------

def test_third_user_cannot_read_or_respond(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller = _make_buyer_seller(app_mod)
    stranger = app_mod.app.test_client()
    _register_and_login(app_mod, stranger, "stranger1")

    resp = buyer.post(
        "/api/quotes/create",
        json={"seller_username": "seller1",
              "items": [{"sku": "X", "name": "n", "qty": 1}]},
    )
    quote_id = resp.get_json()["quote"]["quote_id"]

    resp = stranger.get(f"/api/quotes/{quote_id}")
    assert resp.status_code == 403

    resp = stranger.post(f"/api/quotes/{quote_id}/respond", json={"action": "accept"})
    assert resp.status_code == 403


def test_buyer_cannot_price_seller_cannot_accept(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller = _make_buyer_seller(app_mod)

    resp = buyer.post(
        "/api/quotes/create",
        json={"seller_username": "seller1",
              "items": [{"sku": "X", "name": "n", "qty": 1}]},
    )
    quote_id = resp.get_json()["quote"]["quote_id"]

    # buyer tries to price
    resp = buyer.post(f"/api/quotes/{quote_id}/respond", json={"action": "price", "total_net": 100.0})
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "only_seller_can_price"

    # seller tries to accept
    resp = seller.post(f"/api/quotes/{quote_id}/respond", json={"action": "accept"})
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "only_buyer_can_finalize"


def test_invalid_transition_from_terminal_state(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller = _make_buyer_seller(app_mod)

    resp = buyer.post(
        "/api/quotes/create",
        json={"seller_username": "seller1",
              "items": [{"sku": "X", "name": "n", "qty": 1}]},
    )
    quote_id = resp.get_json()["quote"]["quote_id"]

    # accept -> terminal
    resp = buyer.post(f"/api/quotes/{quote_id}/respond", json={"action": "accept"})
    assert resp.status_code == 200

    # respond again -> reject terminal
    resp = buyer.post(f"/api/quotes/{quote_id}/respond", json={"action": "reject"})
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "terminal_state"

    # seller tries to price a terminal quote
    resp = seller.post(f"/api/quotes/{quote_id}/respond", json={"action": "price", "total_net": 10.0})
    assert resp.status_code == 403


# --- privacy: chain payloads free of company data --------------------------

def test_event_chain_has_no_company_data(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller = _make_buyer_seller(app_mod)

    # set profile with sensitive company data
    buyer.post(
        "/api/b2b/profile",
        json={
            "company_name": "TAJNA-FIRMA-XYZ",
            "nip": "9999999999",
            "billing_address": "Ulica Sekretna 42",
            "contact_email": "sekret@firma.pl",
            "contact_phone": "+48 000 000 000",
        },
    )
    resp = buyer.post(
        "/api/quotes/create",
        json={
            "seller_username": "seller1",
            "items": [{"sku": "BHP-1", "name": "Rekawice", "qty": 3}],
            "note": "pilne",
        },
    )
    quote_id = resp.get_json()["quote"]["quote_id"]
    seller.post(f"/api/quotes/{quote_id}/respond", json={"action": "price", "total_net": 42.0})
    buyer.post(f"/api/quotes/{quote_id}/respond", json={"action": "accept"})

    import json as _json
    events = _read_chain(app_mod, limit=500)
    forbidden = ("TAJNA-FIRMA-XYZ", "9999999999", "Ulica Sekretna", "sekret@firma.pl", "+48 000 000 000")
    for e in events:
        blob = _json.dumps(e, ensure_ascii=False)
        for f in forbidden:
            assert f not in blob, f"Chain leaked '{f}' via event {e.get('type')}"

    # also assert positive-shape: QUOTE_CREATED payload keys don't include leak fields
    created = [e for e in events if e["type"] == "QUOTE_CREATED"]
    assert created, "expected QUOTE_CREATED event"
    payload = created[-1]["payload"]
    for f in ("company_name", "nip", "billing_address", "contact_email", "contact_phone"):
        assert f not in payload
