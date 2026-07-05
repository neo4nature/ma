"""B2B quote (zapytanie ofertowe) HTTP routes for the Workwear/BHP pilot.

Auth: session-based, same as legacy JSON endpoints (see e.g.
`api_account_recovery` in app.py). Session cookie carries `username`;
we resolve to numeric user_id via `get_user_by_username`.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path

from flask import Blueprint, jsonify, request, session

from db import fetch_thread, get_user_by_username, insert_message
from services import b2b_invoice_service as inv_svc
from services import b2b_quote_service as svc


b2b_quotes_bp = Blueprint("b2b_quotes", __name__)


def _base_and_data_dir():
    # Import lazily to avoid circular import at module load.
    import app as legacy_app
    return legacy_app.BASE_DIR, legacy_app.DATA_DIR


def _current_user_id():
    """Return (user_id, username) or (None, None) if not logged in."""
    username = session.get("username")
    if not username:
        return None, None
    base_dir, _ = _base_and_data_dir()
    row = get_user_by_username(base_dir, username)
    if not row:
        return None, None
    return int(row["id"]), username


def _auth_error():
    return jsonify({"ok": False, "error": "auth_required"}), 401


# --- profile ---------------------------------------------------------------

@b2b_quotes_bp.route("/api/b2b/profile", methods=["GET"])
def b2b_profile_get():
    uid, _ = _current_user_id()
    if not uid:
        return _auth_error()
    base_dir, _ = _base_and_data_dir()
    profile = svc.get_profile(base_dir, uid)
    return jsonify({"ok": True, "profile": profile})


@b2b_quotes_bp.route("/api/b2b/profile", methods=["POST"])
def b2b_profile_upsert():
    uid, _ = _current_user_id()
    if not uid:
        return _auth_error()
    data = request.get_json(silent=True) or {}
    base_dir, _ = _base_and_data_dir()
    try:
        profile = svc.upsert_profile(base_dir, uid, data)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "profile": profile})


# --- quotes ----------------------------------------------------------------

@b2b_quotes_bp.route("/api/quotes/create", methods=["POST"])
def b2b_quotes_create():
    uid, _ = _current_user_id()
    if not uid:
        return _auth_error()
    data = request.get_json(silent=True) or {}
    base_dir, data_dir = _base_and_data_dir()

    seller_user_id = svc.resolve_seller(
        base_dir,
        seller_user_id=data.get("seller_user_id"),
        seller_username=data.get("seller_username") or data.get("seller"),
    )
    if not seller_user_id:
        return jsonify({"ok": False, "error": "seller_not_found"}), 400

    items = data.get("items")
    note = data.get("note") or ""
    expires_ts = data.get("expires_ts")

    try:
        quote = svc.create_quote(
            base_dir,
            data_dir=data_dir,
            buyer_user_id=uid,
            seller_user_id=seller_user_id,
            items=items,
            note=note,
            expires_ts=expires_ts,
        )
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "quote": quote}), 201


@b2b_quotes_bp.route("/api/quotes/<quote_id>/respond", methods=["POST"])
def b2b_quotes_respond(quote_id: str):
    uid, _ = _current_user_id()
    if not uid:
        return _auth_error()
    data = request.get_json(silent=True) or {}
    base_dir, data_dir = _base_and_data_dir()
    action = (data.get("action") or "").strip().lower()
    total_net = data.get("total_net")

    try:
        quote = svc.respond_quote(
            base_dir,
            data_dir=data_dir,
            quote_id=quote_id,
            actor_user_id=uid,
            action=action,
            total_net=total_net,
        )
    except LookupError:
        return jsonify({"ok": False, "error": "quote_not_found"}), 404
    except PermissionError as e:
        return jsonify({"ok": False, "error": str(e)}), 403
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "quote": quote})


@b2b_quotes_bp.route("/api/quotes/<quote_id>", methods=["GET"])
def b2b_quotes_get(quote_id: str):
    uid, _ = _current_user_id()
    if not uid:
        return _auth_error()
    base_dir, _ = _base_and_data_dir()
    try:
        quote = svc.get_quote(base_dir, quote_id=quote_id, actor_user_id=uid)
    except LookupError:
        return jsonify({"ok": False, "error": "quote_not_found"}), 404
    except PermissionError as e:
        return jsonify({"ok": False, "error": str(e)}), 403
    return jsonify({"ok": True, "quote": quote})


@b2b_quotes_bp.route("/api/quotes", methods=["GET"])
def b2b_quotes_list():
    """List quotes where current user is buyer OR seller, newest first."""
    uid, _ = _current_user_id()
    if not uid:
        return _auth_error()
    base_dir, _ = _base_and_data_dir()
    quotes = svc.list_quotes(base_dir, uid, limit=100)
    return jsonify({"ok": True, "quotes": quotes})


# --- quote-scoped E2E messenger --------------------------------------------
#
# Reuses the existing X25519 -> HKDF -> AES-GCM stack from `core.comm_crypto`
# via app.py (same helpers legacy `comm_api_send` / `comm_api_thread` use).
# Storage goes through `insert_message` + `fetch_thread` with a `thread_ref`
# scoping the row to a specific quote_id. Legacy comm chat stays unscoped
# (thread_ref = NULL) and its behavior is unchanged.


def _quote_participants_or_403(quote_id: str, uid: int):
    """Return (buyer_id, seller_id) if uid is buyer/seller, else a Flask
    response tuple that the caller should return as-is.
    """
    base_dir, _ = _base_and_data_dir()
    parts = svc.get_quote_participants(base_dir, quote_id)
    if not parts:
        return None, (jsonify({"ok": False, "error": "quote_not_found"}), 404)
    if uid not in (parts["buyer_user_id"], parts["seller_user_id"]):
        return None, (jsonify({"ok": False, "error": "forbidden"}), 403)
    return parts, None


@b2b_quotes_bp.route("/api/quotes/<quote_id>/messages", methods=["POST"])
def b2b_quote_message_send(quote_id: str):
    """Send an E2E-encrypted message scoped to this quote.

    Only buyer or seller of the quote can post. The message is stored with
    thread_ref = quote_id and never leaks into the pair's unscoped comm view.
    No chain event is emitted for chat (chat is not process truth).
    """
    uid, my_username = _current_user_id()
    if not uid:
        return _auth_error()
    parts, err = _quote_participants_or_403(quote_id, uid)
    if err:
        return err

    data = request.get_json(silent=True) or {}
    text = (data.get("text") or data.get("body") or "").strip()
    if not text:
        return jsonify({"ok": False, "error": "missing_text"}), 400

    base_dir, _ = _base_and_data_dir()
    # peer = the OTHER party of this quote
    peer_uid = parts["seller_user_id"] if uid == parts["buyer_user_id"] else parts["buyer_user_id"]
    peer_username = svc.get_username_by_id(base_dir, peer_uid)
    if not peer_username:
        return jsonify({"ok": False, "error": "peer_not_found"}), 400

    # Reuse the same crypto stack the legacy messenger uses. Lazy import via
    # `legacy_app` (same pattern already in this module) to avoid circular
    # imports at module load.
    import app as legacy_app
    legacy_app.ensure_user_records([my_username, peer_username])

    sender_kp = legacy_app.ensure_comm_keypair(my_username, Path(legacy_app.COMM_KEYS_DIR))
    receiver_kp = legacy_app.ensure_comm_keypair(peer_username, Path(legacy_app.COMM_KEYS_DIR))

    msg_id = str(uuid.uuid4())
    ts = time.time()
    aad = f"{my_username}->{peer_username}|{msg_id}|{ts}|quote:{quote_id}".encode("utf-8")
    ct, nonce, salt = legacy_app.encrypt_for_pair(
        sender_kp.private_key, receiver_kp.public_key, text.encode("utf-8"), aad
    )

    insert_message(
        base_dir,
        {
            "id": msg_id,
            "sender": my_username,
            "receiver": peer_username,
            "timestamp": ts,
            "ciphertext_b64": legacy_app._b64e(ct),
            "nonce_b64": legacy_app._b64e(nonce),
            "salt_b64": legacy_app._b64e(salt),
            "aad_b64": legacy_app._b64e(aad),
            "v": 1,
            "thread_ref": quote_id,
        },
    )
    return jsonify({
        "ok": True,
        "message": {
            "id": msg_id,
            "sender": my_username,
            "receiver": peer_username,
            "timestamp": ts,
            "thread_ref": quote_id,
        },
    }), 201


@b2b_quotes_bp.route("/api/quotes/<quote_id>/messages", methods=["GET"])
def b2b_quote_message_thread(quote_id: str):
    """Return the decrypted message thread scoped to this quote.

    Only buyer or seller can read. Rows are filtered by thread_ref=quote_id,
    so the same buyer/seller pair can hold separate conversations per quote.
    """
    uid, my_username = _current_user_id()
    if not uid:
        return _auth_error()
    parts, err = _quote_participants_or_403(quote_id, uid)
    if err:
        return err

    base_dir, _ = _base_and_data_dir()
    peer_uid = parts["seller_user_id"] if uid == parts["buyer_user_id"] else parts["buyer_user_id"]
    peer_username = svc.get_username_by_id(base_dir, peer_uid)
    if not peer_username:
        return jsonify({"ok": False, "error": "peer_not_found"}), 400

    import app as legacy_app
    legacy_app.ensure_user_records([my_username, peer_username])

    rows = fetch_thread(base_dir, my_username, peer_username, limit=200, thread_ref=quote_id)

    my_kp = legacy_app.ensure_comm_keypair(my_username, Path(legacy_app.COMM_KEYS_DIR))
    peer_kp = legacy_app.ensure_comm_keypair(peer_username, Path(legacy_app.COMM_KEYS_DIR))

    out = []
    for m in rows:
        body = None
        try:
            aad = legacy_app._b64d(m.get("aad_b64", ""))
            ct = legacy_app._b64d(m.get("ciphertext_b64", ""))
            nonce = legacy_app._b64d(m.get("nonce_b64", ""))
            salt = legacy_app._b64d(m.get("salt_b64", ""))
            sender = m.get("sender")
            receiver = m.get("receiver")
            if sender == my_username and receiver == peer_username:
                body = legacy_app.decrypt_for_pair(
                    peer_kp.private_key, my_kp.public_key, ct, nonce, salt, aad
                ).decode("utf-8", errors="replace")
            elif sender == peer_username and receiver == my_username:
                body = legacy_app.decrypt_for_pair(
                    my_kp.private_key, peer_kp.public_key, ct, nonce, salt, aad
                ).decode("utf-8", errors="replace")
            else:
                body = "[encrypted]"
        except Exception:
            body = "[decrypt_error]"

        out.append({
            "id": m.get("msg_id") or m.get("id"),
            "sender": m.get("sender"),
            "receiver": m.get("receiver"),
            "timestamp": m.get("ts") or m.get("timestamp") or 0,
            "body": body,
            "thread_ref": m.get("thread_ref"),
        })
    return jsonify({"ok": True, "quote_id": quote_id, "messages": out})


# --- Phase 3: offline invoices ----------------------------------------------
#
# Seller issues one invoice per ACCEPTED quote, then confirms the offline
# payment and completes the order. No PDF, no numbering — `external_ref`
# stores the number from the external invoicing system as an opaque string.


def _invoice_error(e):
    """Map service exceptions to the same JSON error shape as quote routes."""
    if isinstance(e, LookupError):
        return jsonify({"ok": False, "error": str(e)}), 404
    if isinstance(e, PermissionError):
        return jsonify({"ok": False, "error": str(e)}), 403
    return jsonify({"ok": False, "error": str(e)}), 400


@b2b_quotes_bp.route("/api/quotes/<quote_id>/invoice", methods=["POST"])
def b2b_invoice_issue(quote_id: str):
    uid, _ = _current_user_id()
    if not uid:
        return _auth_error()
    data = request.get_json(silent=True) or {}
    base_dir, data_dir = _base_and_data_dir()

    vat_rate = data.get("vat_rate")
    if vat_rate is None:
        vat_rate = 23.0
    external_ref = data.get("external_ref")
    if external_ref is not None:
        external_ref = str(external_ref).strip()
        if len(external_ref) > 100:
            return jsonify({"ok": False, "error": "external_ref_too_long"}), 400
        external_ref = external_ref or None

    try:
        invoice = inv_svc.issue_invoice(
            base_dir,
            data_dir,
            quote_id=quote_id,
            actor_user_id=uid,
            vat_rate=vat_rate,
            external_ref=external_ref,
        )
    except (LookupError, PermissionError, ValueError) as e:
        return _invoice_error(e)
    return jsonify({"ok": True, "invoice": invoice}), 201


@b2b_quotes_bp.route("/api/invoices/<invoice_id>/confirm-payment", methods=["POST"])
def b2b_invoice_confirm_payment(invoice_id: str):
    uid, _ = _current_user_id()
    if not uid:
        return _auth_error()
    base_dir, data_dir = _base_and_data_dir()
    try:
        invoice = inv_svc.confirm_payment(
            base_dir, data_dir, invoice_id=invoice_id, actor_user_id=uid
        )
    except (LookupError, PermissionError, ValueError) as e:
        return _invoice_error(e)
    return jsonify({"ok": True, "invoice": invoice})


@b2b_quotes_bp.route("/api/invoices/<invoice_id>/complete", methods=["POST"])
def b2b_invoice_complete(invoice_id: str):
    uid, _ = _current_user_id()
    if not uid:
        return _auth_error()
    base_dir, data_dir = _base_and_data_dir()
    try:
        invoice = inv_svc.complete_order(
            base_dir, data_dir, invoice_id=invoice_id, actor_user_id=uid
        )
    except (LookupError, PermissionError, ValueError) as e:
        return _invoice_error(e)
    return jsonify({"ok": True, "invoice": invoice})


@b2b_quotes_bp.route("/api/invoices/<invoice_id>", methods=["GET"])
def b2b_invoice_get(invoice_id: str):
    uid, _ = _current_user_id()
    if not uid:
        return _auth_error()
    base_dir, _ = _base_and_data_dir()
    try:
        invoice = inv_svc.get_invoice(base_dir, invoice_id=invoice_id, actor_user_id=uid)
    except (LookupError, PermissionError) as e:
        return _invoice_error(e)
    return jsonify({"ok": True, "invoice": invoice})


@b2b_quotes_bp.route("/api/invoices", methods=["GET"])
def b2b_invoice_list():
    """List invoices where current user is buyer OR seller, newest first."""
    uid, _ = _current_user_id()
    if not uid:
        return _auth_error()
    base_dir, _ = _base_and_data_dir()
    invoices = inv_svc.list_invoices(base_dir, uid, limit=100)
    return jsonify({"ok": True, "invoices": invoices})


@b2b_quotes_bp.route("/api/quotes/<quote_id>/invoice", methods=["GET"])
def b2b_invoice_for_quote(quote_id: str):
    """Invoice for a quote — 200 with invoice=null when not yet issued."""
    uid, _ = _current_user_id()
    if not uid:
        return _auth_error()
    base_dir, _ = _base_and_data_dir()
    try:
        invoice = inv_svc.get_invoice_for_quote(base_dir, quote_id=quote_id, actor_user_id=uid)
    except (LookupError, PermissionError) as e:
        return _invoice_error(e)
    return jsonify({"ok": True, "invoice": invoice})
