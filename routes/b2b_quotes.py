"""B2B quote (zapytanie ofertowe) HTTP routes for the Workwear/BHP pilot.

Auth: session-based, same as legacy JSON endpoints (see e.g.
`api_account_recovery` in app.py). Session cookie carries `username`;
we resolve to numeric user_id via `get_user_by_username`.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request, session

from db import get_user_by_username
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
