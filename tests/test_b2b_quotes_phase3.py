"""B2B quote Phase 3 tests — offline invoices.

Covers:
- happy path: create -> price -> accept -> issue invoice -> confirm-payment
  -> complete, with VAT math at 23% and chain events INVOICE_ISSUED /
  PAYMENT_CONFIRMED / ORDER_COMPLETED (payloads free of company data)
- issue guards: quote not ACCEPTED, buyer cannot issue, double issue
- payment/complete guards: buyer forbidden, bad_status transitions
- get_invoice authorization (third user 403)
- external_ref stored and returned (but never on the chain)
- GET /api/invoices list for buyer/seller/third party
- GET /api/quotes/<id>/invoice returns invoice=null before issuing
"""

from __future__ import annotations

import importlib
import json
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


def _make_three_clients(app_mod):
    buyer = app_mod.app.test_client()
    seller = app_mod.app.test_client()
    stranger = app_mod.app.test_client()
    _register_and_login(app_mod, buyer, "buyer1")
    _register_and_login(app_mod, seller, "seller1")
    _register_and_login(app_mod, stranger, "stranger1")
    return buyer, seller, stranger


def _read_chain(app_mod, limit=500):
    from core.event_chain import read_events
    log = Path(app_mod.DATA_DIR) / "event_chain" / "event_chain.jsonl"
    state = Path(app_mod.DATA_DIR) / "event_chain" / "event_chain_state.json"
    events, _ = read_events(log_path=log, state_path=state, limit=limit, verify=False)
    return events


def _create_quote(buyer, items=None):
    payload = {
        "seller_username": "seller1",
        "items": items or [{"sku": "BHP-1", "name": "Rekawice", "qty": 10}],
    }
    resp = buyer.post("/api/quotes/create", json=payload)
    assert resp.status_code == 201, resp.get_data(as_text=True)
    return resp.get_json()["quote"]["quote_id"]


def _accepted_quote(buyer, seller, total_net=100.0):
    """create -> price -> accept; returns quote_id."""
    quote_id = _create_quote(buyer)
    resp = seller.post(
        f"/api/quotes/{quote_id}/respond",
        json={"action": "price", "total_net": total_net},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    resp = buyer.post(f"/api/quotes/{quote_id}/respond", json={"action": "accept"})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return quote_id


# --- 1. happy path ----------------------------------------------------------

def test_full_invoice_happy_path(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller, _ = _make_three_clients(app_mod)

    # give both sides company profiles so any leak would be observable
    buyer.post("/api/b2b/profile", json={
        "company_name": "Kupiec Sp. z o.o.", "nip": "1111111111",
        "billing_address": "ul. Kupna 1", "contact_email": "k@x.pl",
        "contact_phone": "111",
    })
    seller.post("/api/b2b/profile", json={
        "company_name": "Rawpol Sp. z o.o.", "nip": "5252525252",
        "billing_address": "ul. Robocza 1", "contact_email": "r@x.pl",
        "contact_phone": "222",
    })

    quote_id = _accepted_quote(buyer, seller, total_net=100.0)

    # no invoice yet — GET returns 200 with invoice=null
    resp = buyer.get(f"/api/quotes/{quote_id}/invoice")
    assert resp.status_code == 200
    assert resp.get_json() == {"ok": True, "invoice": None}

    # seller issues invoice at default 23% VAT
    resp = seller.post(f"/api/quotes/{quote_id}/invoice", json={})
    assert resp.status_code == 201, resp.get_data(as_text=True)
    inv = resp.get_json()["invoice"]
    assert inv["quote_id"] == quote_id
    assert inv["status"] == "ISSUED"
    assert inv["amount_net"] == 100.0
    assert inv["vat_rate"] == 23.0
    assert inv["vat_amount"] == 23.0
    assert inv["amount_gross"] == 123.0
    assert inv["currency"] == "PLN"
    assert inv["issued_ts"] > 0
    assert inv["paid_ts"] is None
    invoice_id = inv["invoice_id"]

    # buyer sees it via quote lookup too
    resp = buyer.get(f"/api/quotes/{quote_id}/invoice")
    assert resp.status_code == 200
    assert resp.get_json()["invoice"]["invoice_id"] == invoice_id

    # seller confirms payment
    resp = seller.post(f"/api/invoices/{invoice_id}/confirm-payment")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    inv = resp.get_json()["invoice"]
    assert inv["status"] == "PAID"
    assert inv["paid_ts"] > 0

    # seller completes the order
    resp = seller.post(f"/api/invoices/{invoice_id}/complete")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    inv = resp.get_json()["invoice"]
    assert inv["status"] == "COMPLETED"
    assert inv["completed_ts"] > 0

    # chain has all three process events, in order
    events = _read_chain(app_mod)
    types = [e["type"] for e in events]
    for etype in ("INVOICE_ISSUED", "PAYMENT_CONFIRMED", "ORDER_COMPLETED"):
        assert etype in types, types
    assert types.index("INVOICE_ISSUED") < types.index("PAYMENT_CONFIRMED") < types.index("ORDER_COMPLETED")

    issued = next(e for e in events if e["type"] == "INVOICE_ISSUED")
    assert issued["payload"]["invoice_id"] == invoice_id
    assert issued["payload"]["quote_id"] == quote_id
    assert issued["payload"]["amount_net"] == 100.0
    assert issued["payload"]["vat_rate"] == 23.0
    assert issued["payload"]["amount_gross"] == 123.0
    paid = next(e for e in events if e["type"] == "PAYMENT_CONFIRMED")
    assert paid["payload"]["amount_gross"] == 123.0
    done = next(e for e in events if e["type"] == "ORDER_COMPLETED")
    assert done["payload"] == {"invoice_id": invoice_id, "quote_id": quote_id}

    # privacy: NO company data anywhere on the chain
    blob = json.dumps(events, ensure_ascii=False)
    for forbidden in ("Rawpol", "Kupiec", "5252525252", "1111111111",
                      "Robocza", "Kupna", "company", "nip"):
        assert forbidden not in blob, f"chain leaked: {forbidden}"


# --- 2. issue guards ----------------------------------------------------------

def test_issue_before_accept_rejected(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller, _ = _make_three_clients(app_mod)
    quote_id = _create_quote(buyer)
    seller.post(f"/api/quotes/{quote_id}/respond", json={"action": "price", "total_net": 100.0})

    resp = seller.post(f"/api/quotes/{quote_id}/invoice", json={})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "quote_not_accepted"


def test_issue_by_buyer_forbidden(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller, _ = _make_three_clients(app_mod)
    quote_id = _accepted_quote(buyer, seller)

    resp = buyer.post(f"/api/quotes/{quote_id}/invoice", json={})
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "not_seller"


def test_second_invoice_rejected(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller, _ = _make_three_clients(app_mod)
    quote_id = _accepted_quote(buyer, seller)

    resp = seller.post(f"/api/quotes/{quote_id}/invoice", json={})
    assert resp.status_code == 201
    resp = seller.post(f"/api/quotes/{quote_id}/invoice", json={})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invoice_exists"


def test_issue_bad_vat_rate(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller, _ = _make_three_clients(app_mod)
    quote_id = _accepted_quote(buyer, seller)

    resp = seller.post(f"/api/quotes/{quote_id}/invoice", json={"vat_rate": 101})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "bad_vat_rate"
    resp = seller.post(f"/api/quotes/{quote_id}/invoice", json={"vat_rate": -1})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "bad_vat_rate"


def test_issue_on_missing_quote_404(tmp_path):
    app_mod = _load_app(tmp_path)
    _, seller, _ = _make_three_clients(app_mod)
    resp = seller.post("/api/quotes/nope/invoice", json={})
    assert resp.status_code == 404
    assert resp.get_json()["error"] == "quote_not_found"


# --- 3. payment / complete guards --------------------------------------------

def _issued_invoice(buyer, seller, **kwargs):
    quote_id = _accepted_quote(buyer, seller)
    resp = seller.post(f"/api/quotes/{quote_id}/invoice", json=kwargs)
    assert resp.status_code == 201, resp.get_data(as_text=True)
    return quote_id, resp.get_json()["invoice"]["invoice_id"]


def test_confirm_payment_by_buyer_forbidden(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller, _ = _make_three_clients(app_mod)
    _, invoice_id = _issued_invoice(buyer, seller)

    resp = buyer.post(f"/api/invoices/{invoice_id}/confirm-payment")
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "not_seller"


def test_confirm_payment_twice_bad_status(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller, _ = _make_three_clients(app_mod)
    _, invoice_id = _issued_invoice(buyer, seller)

    resp = seller.post(f"/api/invoices/{invoice_id}/confirm-payment")
    assert resp.status_code == 200
    resp = seller.post(f"/api/invoices/{invoice_id}/confirm-payment")
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "bad_status:PAID"


def test_complete_without_payment_bad_status(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller, _ = _make_three_clients(app_mod)
    _, invoice_id = _issued_invoice(buyer, seller)

    resp = seller.post(f"/api/invoices/{invoice_id}/complete")
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "bad_status:ISSUED"


def test_complete_by_buyer_forbidden(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller, _ = _make_three_clients(app_mod)
    _, invoice_id = _issued_invoice(buyer, seller)
    seller.post(f"/api/invoices/{invoice_id}/confirm-payment")

    resp = buyer.post(f"/api/invoices/{invoice_id}/complete")
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "not_seller"


# --- 4. read authorization ----------------------------------------------------

def test_get_invoice_third_user_forbidden(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller, stranger = _make_three_clients(app_mod)
    quote_id, invoice_id = _issued_invoice(buyer, seller)

    # both parties can read
    assert buyer.get(f"/api/invoices/{invoice_id}").status_code == 200
    assert seller.get(f"/api/invoices/{invoice_id}").status_code == 200
    # stranger cannot — neither directly nor via the quote
    resp = stranger.get(f"/api/invoices/{invoice_id}")
    assert resp.status_code == 403
    resp = stranger.get(f"/api/quotes/{quote_id}/invoice")
    assert resp.status_code == 403


def test_invoice_endpoints_require_auth(tmp_path):
    app_mod = _load_app(tmp_path)
    anon = app_mod.app.test_client()
    assert anon.get("/api/invoices").status_code == 401
    assert anon.get("/api/invoices/x").status_code == 401
    assert anon.post("/api/invoices/x/confirm-payment").status_code == 401
    assert anon.post("/api/invoices/x/complete").status_code == 401
    assert anon.post("/api/quotes/x/invoice", json={}).status_code == 401
    assert anon.get("/api/quotes/x/invoice").status_code == 401


# --- 5. external_ref ------------------------------------------------------------

def test_external_ref_stored_and_returned(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller, _ = _make_three_clients(app_mod)
    _, invoice_id = _issued_invoice(buyer, seller, external_ref="  FV/2026/07/0042  ")

    resp = buyer.get(f"/api/invoices/{invoice_id}")
    assert resp.status_code == 200
    inv = resp.get_json()["invoice"]
    assert inv["external_ref"] == "FV/2026/07/0042"

    # external_ref never leaks onto the chain
    blob = json.dumps(_read_chain(app_mod), ensure_ascii=False)
    assert "FV/2026/07/0042" not in blob


def test_external_ref_too_long_rejected(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller, _ = _make_three_clients(app_mod)
    quote_id = _accepted_quote(buyer, seller)

    resp = seller.post(f"/api/quotes/{quote_id}/invoice", json={"external_ref": "X" * 101})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "external_ref_too_long"


# --- 6. list ---------------------------------------------------------------------

def test_list_invoices_visibility(tmp_path):
    app_mod = _load_app(tmp_path)
    buyer, seller, stranger = _make_three_clients(app_mod)
    _, inv1 = _issued_invoice(buyer, seller)
    _, inv2 = _issued_invoice(buyer, seller)

    resp = buyer.get("/api/invoices")
    assert resp.status_code == 200
    ids = [i["invoice_id"] for i in resp.get_json()["invoices"]]
    assert inv1 in ids and inv2 in ids
    # newest first
    assert ids.index(inv2) < ids.index(inv1)

    resp = seller.get("/api/invoices")
    ids = [i["invoice_id"] for i in resp.get_json()["invoices"]]
    assert inv1 in ids and inv2 in ids

    resp = stranger.get("/api/invoices")
    assert resp.status_code == 200
    assert resp.get_json()["invoices"] == []


# --- 7. route inventory ------------------------------------------------------------

def test_phase3_routes_registered(tmp_path):
    app_mod = _load_app(tmp_path)
    rules = {r.rule for r in app_mod.app.url_map.iter_rules()}
    assert "/api/quotes/<quote_id>/invoice" in rules
    assert "/api/invoices/<invoice_id>/confirm-payment" in rules
    assert "/api/invoices/<invoice_id>/complete" in rules
    assert "/api/invoices/<invoice_id>" in rules
    assert "/api/invoices" in rules
