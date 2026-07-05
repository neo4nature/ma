"""B2B quote (zapytanie ofertowe) service for the Workwear/BHP pilot.

Design notes
------------
- Payment model is OFFLINE_INVOICE only. No LifeCoin, no settlement, no wallet.
- SQLite holds personal / company data (company_name, NIP, address, contacts).
- The append-only event chain stores PROCESS truth only:
  quote_id, actor, status, item skus/qtys, total_net, hashes.
  Company names, NIP, address and contact fields are NEVER written to the
  event chain — they stay in the local SQLite tables.
- Status transitions:
    (new)  -> SENT           (create_quote goes straight to SENT)
    SENT   -> SENT           (seller 'price' — updates total_net, still SENT)
    SENT   -> ACCEPTED       (buyer 'accept')
    SENT   -> REJECTED       (buyer 'reject')
    ACCEPTED/REJECTED/EXPIRED -> terminal (no transitions)
    Any read past expires_ts reads as EXPIRED (soft: DB row untouched unless
    it later transitions; read view masks stale SENT into EXPIRED).
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.event_chain import append_event
from db import connect, get_user_by_username


# --- Neo's bulk_only rule --------------------------------------------------
# If a per-unit price is lower than the transport cost, we require the
# order to hit a minimum multiple of transport cost — otherwise transport
# eats the margin. Configurable via env; default 30 PLN transport (Neo,
# 2026-07-05), 5x cushion (so target minimum order value = 150 PLN for a
# low-value SKU). Future refinement: compute from Rawpol's weight/zone
# shipping price list instead of a flat rate.
TRANSPORT_COST_PLN = float(os.getenv("MA_TRANSPORT_COST_PLN", "30.0"))
BULK_ONLY_MULTIPLIER = 5


# --- paths -----------------------------------------------------------------

def _chain_paths(data_dir: str) -> Dict[str, Path]:
    root = Path(data_dir) / "event_chain"
    return {
        "log": root / "event_chain.jsonl",
        "state": root / "event_chain_state.json",
    }


# --- profile ---------------------------------------------------------------

_PROFILE_FIELDS = (
    "company_name",
    "nip",
    "billing_address",
    "contact_email",
    "contact_phone",
)


def upsert_profile(base_dir: str, user_id: int, fields: Dict[str, Any]) -> Dict[str, Any]:
    """Create or update the b2b_profile for user_id. UNIQUE(user_id) enforces one row."""
    user_id = int(user_id)
    if user_id <= 0:
        raise ValueError("bad_user_id")
    clean = {k: (str(fields.get(k)).strip() if fields.get(k) is not None else None) for k in _PROFILE_FIELDS}

    conn = connect(base_dir)
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM b2b_profiles WHERE user_id=?", (user_id,))
        row = cur.fetchone()
        now = time.time()
        if row:
            cur.execute(
                """UPDATE b2b_profiles
                   SET company_name=?, nip=?, billing_address=?, contact_email=?, contact_phone=?
                   WHERE user_id=?""",
                (
                    clean["company_name"],
                    clean["nip"],
                    clean["billing_address"],
                    clean["contact_email"],
                    clean["contact_phone"],
                    user_id,
                ),
            )
        else:
            cur.execute(
                """INSERT INTO b2b_profiles
                     (user_id, company_name, nip, billing_address, contact_email, contact_phone, created_ts)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    user_id,
                    clean["company_name"],
                    clean["nip"],
                    clean["billing_address"],
                    clean["contact_email"],
                    clean["contact_phone"],
                    now,
                ),
            )
        conn.commit()
    finally:
        conn.close()
    return get_profile(base_dir, user_id) or {}


def get_profile(base_dir: str, user_id: int) -> Optional[Dict[str, Any]]:
    conn = connect(base_dir)
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM b2b_profiles WHERE user_id=?", (int(user_id),))
        row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return dict(row)


# --- quotes ----------------------------------------------------------------

def _normalize_items(items: Any) -> List[Dict[str, Any]]:
    """Normalize items list to a stable shape.

    Each item: {listing_id or sku, name, qty, unit_price_net (nullable)}.
    """
    if not isinstance(items, list) or not items:
        raise ValueError("empty_items")
    out: List[Dict[str, Any]] = []
    for raw in items:
        if not isinstance(raw, dict):
            raise ValueError("bad_item")
        listing_id = (raw.get("listing_id") or "").strip() if raw.get("listing_id") else ""
        sku = (raw.get("sku") or "").strip() if raw.get("sku") else ""
        if not listing_id and not sku:
            raise ValueError("item_missing_id")
        name = (raw.get("name") or "").strip()
        try:
            qty = int(raw.get("qty") or 0)
        except Exception:
            raise ValueError("bad_qty")
        if qty <= 0:
            raise ValueError("bad_qty")
        unit_price_net = raw.get("unit_price_net")
        if unit_price_net is not None:
            try:
                unit_price_net = float(unit_price_net)
            except Exception:
                raise ValueError("bad_unit_price")
        out.append({
            "listing_id": listing_id or None,
            "sku": sku or None,
            "name": name,
            "qty": qty,
            "unit_price_net": unit_price_net,
        })
    return out


def _items_process_summary(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Chain-safe projection: ids + qty only. NO 'name' (may leak client info)."""
    return [
        {
            "listing_id": it.get("listing_id"),
            "sku": it.get("sku"),
            "qty": int(it.get("qty") or 0),
        }
        for it in items
    ]


def _items_hash(items: List[Dict[str, Any]]) -> str:
    payload = json.dumps(_items_process_summary(items), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _row_to_dict(row) -> Dict[str, Any]:
    d = dict(row)
    try:
        d["items"] = json.loads(d.pop("items_json", "[]") or "[]")
    except Exception:
        d["items"] = []
    return d


def _enforce_bulk_only(items: List[Dict[str, Any]]) -> None:
    """Neo's rule: if unit_price_net is set AND < transport, require bulk.

    Items without unit_price_net (open inquiry — buyer asks for a price)
    are NOT checked here; the transport-cost floor is enforced later on
    the seller's price action via `respond_quote`.
    """
    threshold = TRANSPORT_COST_PLN
    target = BULK_ONLY_MULTIPLIER * TRANSPORT_COST_PLN
    for it in items:
        price = it.get("unit_price_net")
        if price is None:
            continue
        try:
            price_f = float(price)
        except Exception:
            continue
        if price_f <= 0 or price_f >= threshold:
            continue
        qty = int(it.get("qty") or 0)
        if qty * price_f >= target:
            continue
        ident = it.get("sku") or it.get("listing_id") or "?"
        min_qty = int(math.ceil(target / price_f))
        raise ValueError(f"bulk_only:{ident}:min_qty={min_qty}")


def _effective_status(row: Dict[str, Any], now: float | None = None) -> str:
    now = now if now is not None else time.time()
    status = str(row.get("status") or "")
    expires_ts = row.get("expires_ts")
    if status == "SENT" and expires_ts is not None and float(expires_ts) < now:
        return "EXPIRED"
    return status


def create_quote(
    base_dir: str,
    *,
    data_dir: str,
    buyer_user_id: int,
    seller_user_id: int,
    items: Any,
    note: str = "",
    expires_ts: Optional[float] = None,
) -> Dict[str, Any]:
    buyer_user_id = int(buyer_user_id)
    seller_user_id = int(seller_user_id)
    if buyer_user_id <= 0 or seller_user_id <= 0:
        raise ValueError("bad_user_id")
    if buyer_user_id == seller_user_id:
        raise ValueError("cannot_quote_self")

    norm_items = _normalize_items(items)
    _enforce_bulk_only(norm_items)
    quote_id = uuid.uuid4().hex
    now = time.time()
    note_str = (note or "").strip()

    conn = connect(base_dir)
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO b2b_quotes
                 (quote_id, buyer_user_id, seller_user_id, items_json, total_net,
                  currency, status, note, payment_method, created_ts, updated_ts, expires_ts)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                quote_id,
                buyer_user_id,
                seller_user_id,
                json.dumps(norm_items, ensure_ascii=False, separators=(",", ":")),
                None,
                "PLN",
                "SENT",
                note_str,
                "OFFLINE_INVOICE",
                now,
                now,
                float(expires_ts) if expires_ts is not None else None,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    paths = _chain_paths(data_dir)
    items_hash = _items_hash(norm_items)
    # QUOTE_CREATED then QUOTE_SENT — buyer submits inquiry directly.
    _emit(paths, "QUOTE_CREATED", {
        "quote_id": quote_id,
        "buyer_user_id": buyer_user_id,
        "seller_user_id": seller_user_id,
        "items": _items_process_summary(norm_items),
        "items_hash": items_hash,
        "payment_method": "OFFLINE_INVOICE",
        "currency": "PLN",
    })
    _emit(paths, "QUOTE_SENT", {
        "quote_id": quote_id,
        "items_hash": items_hash,
    })

    return _load_quote_row(base_dir, quote_id) or {}


def respond_quote(
    base_dir: str,
    *,
    data_dir: str,
    quote_id: str,
    actor_user_id: int,
    action: str,
    total_net: Optional[float] = None,
) -> Dict[str, Any]:
    quote_id = (quote_id or "").strip()
    actor_user_id = int(actor_user_id)
    action = (action or "").strip().lower()

    if action not in ("price", "accept", "reject"):
        raise ValueError("bad_action")

    row = _load_quote_row(base_dir, quote_id)
    if not row:
        raise LookupError("quote_not_found")

    eff_status = _effective_status(row)
    if eff_status in ("ACCEPTED", "REJECTED", "EXPIRED"):
        raise PermissionError("terminal_state")
    if eff_status != "SENT":
        raise PermissionError("bad_state")

    buyer_id = int(row["buyer_user_id"])
    seller_id = int(row["seller_user_id"])
    now = time.time()

    paths = _chain_paths(data_dir)

    if action == "price":
        if actor_user_id != seller_id:
            raise PermissionError("only_seller_can_price")
        if total_net is None:
            raise ValueError("missing_total_net")
        try:
            total_net_f = float(total_net)
        except Exception:
            raise ValueError("bad_total_net")
        if total_net_f < 0:
            raise ValueError("bad_total_net")
        # Neo's floor: an offer priced below transport cost is never worth
        # sending as a B2B order.
        if total_net_f < TRANSPORT_COST_PLN:
            raise ValueError("total_below_transport")
        conn = connect(base_dir)
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE b2b_quotes SET total_net=?, updated_ts=? WHERE quote_id=?",
                (total_net_f, now, quote_id),
            )
            conn.commit()
        finally:
            conn.close()
        _emit(paths, "QUOTE_PRICED", {
            "quote_id": quote_id,
            "actor_user_id": actor_user_id,
            "total_net": total_net_f,
            "currency": str(row.get("currency") or "PLN"),
        })
        return _load_quote_row(base_dir, quote_id) or {}

    # accept / reject -> buyer only
    if actor_user_id != buyer_id:
        raise PermissionError("only_buyer_can_finalize")

    new_status = "ACCEPTED" if action == "accept" else "REJECTED"
    conn = connect(base_dir)
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE b2b_quotes SET status=?, updated_ts=? WHERE quote_id=?",
            (new_status, now, quote_id),
        )
        conn.commit()
    finally:
        conn.close()

    etype = "QUOTE_ACCEPTED" if action == "accept" else "QUOTE_REJECTED"
    _emit(paths, etype, {
        "quote_id": quote_id,
        "actor_user_id": actor_user_id,
        "total_net": row.get("total_net"),
        "currency": str(row.get("currency") or "PLN"),
    })
    return _load_quote_row(base_dir, quote_id) or {}


def list_quotes(base_dir: str, user_id: int, limit: int = 100) -> List[Dict[str, Any]]:
    """Return quotes where user is buyer OR seller, newest first.

    Effective status (EXPIRED for stale SENT rows) is surfaced without
    mutating the DB row — same read-view convention as `get_quote`.
    """
    user_id = int(user_id)
    if user_id <= 0:
        return []
    limit = max(1, min(500, int(limit)))
    conn = connect(base_dir)
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT * FROM b2b_quotes
               WHERE buyer_user_id=? OR seller_user_id=?
               ORDER BY created_ts DESC
               LIMIT ?""",
            (user_id, user_id, limit),
        )
        rows = cur.fetchall()
    finally:
        conn.close()
    now = time.time()
    out: List[Dict[str, Any]] = []
    for r in rows:
        row = _row_to_dict(r)
        row["status"] = _effective_status(row, now)
        out.append(row)
    return out


def get_quote(base_dir: str, *, quote_id: str, actor_user_id: int) -> Dict[str, Any]:
    row = _load_quote_row(base_dir, (quote_id or "").strip())
    if not row:
        raise LookupError("quote_not_found")
    actor_user_id = int(actor_user_id)
    if actor_user_id not in (int(row["buyer_user_id"]), int(row["seller_user_id"])):
        raise PermissionError("forbidden")
    # surface effective status (expired) without mutating DB row
    row["status"] = _effective_status(row)
    return row


# --- internal helpers ------------------------------------------------------

def _load_quote_row(base_dir: str, quote_id: str) -> Optional[Dict[str, Any]]:
    if not quote_id:
        return None
    conn = connect(base_dir)
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM b2b_quotes WHERE quote_id=?", (quote_id,))
        row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return _row_to_dict(row)


def _emit(paths: Dict[str, Path], etype: str, payload: Dict[str, Any]) -> None:
    try:
        append_event(
            log_path=paths["log"],
            state_path=paths["state"],
            etype=etype,
            payload=payload,
        )
    except Exception:
        # Chain is best-effort for the pilot; SQLite remains truth-of-record.
        pass


def get_username_by_id(base_dir: str, user_id: int) -> Optional[str]:
    """Small helper: user_id -> username, or None. Used by message routes."""
    try:
        uid = int(user_id)
    except Exception:
        return None
    if uid <= 0:
        return None
    conn = connect(base_dir)
    try:
        cur = conn.cursor()
        cur.execute("SELECT username FROM users WHERE id=?", (uid,))
        row = cur.fetchone()
    finally:
        conn.close()
    return str(row["username"]) if row else None


def get_quote_participants(base_dir: str, quote_id: str) -> Optional[Dict[str, int]]:
    """Cheap helper for message endpoints: return {buyer_user_id, seller_user_id}
    or None if the quote does not exist. Does NOT enforce auth.
    """
    row = _load_quote_row(base_dir, (quote_id or "").strip())
    if not row:
        return None
    return {
        "buyer_user_id": int(row["buyer_user_id"]),
        "seller_user_id": int(row["seller_user_id"]),
    }


def resolve_seller(base_dir: str, *, seller_user_id: Any = None, seller_username: Any = None) -> Optional[int]:
    """Route helper: accept either seller_user_id or seller username."""
    if seller_user_id is not None:
        try:
            uid = int(seller_user_id)
        except Exception:
            uid = 0
        if uid > 0:
            conn = connect(base_dir)
            try:
                cur = conn.cursor()
                cur.execute("SELECT id FROM users WHERE id=?", (uid,))
                row = cur.fetchone()
            finally:
                conn.close()
            if row:
                return uid
    if seller_username:
        row = get_user_by_username(base_dir, str(seller_username).strip())
        if row:
            return int(row["id"])
    return None
