"""B2B offline invoice service for the Workwear/BHP pilot (Phase 3).

Design notes
------------
- Payment model is OFFLINE_INVOICE only. No LifeCoin, no settlement, no wallet.
- One invoice per quote (UNIQUE(quote_id)). The invoice is issued by the
  SELLER after the buyer has ACCEPTED a priced quote.
- No PDF generation and no invoice numbering here — `external_ref` is an
  opaque string holding the number from the external invoicing system
  (e.g. Faktura.pl). It stays in SQLite only.
- The append-only event chain stores PROCESS truth only:
  invoice_id, quote_id, amounts, vat_rate, currency, statuses.
  Company names, NIP, address, contacts and external_ref are NEVER written
  to the event chain — they stay in the local SQLite tables.
- Status transitions:
    (new)  -> ISSUED         (issue_invoice, quote must be ACCEPTED)
    ISSUED -> PAID           (confirm_payment — seller confirms offline payment)
    PAID   -> COMPLETED      (complete_order — seller marks order done)
    COMPLETED -> terminal
"""

from __future__ import annotations

import sqlite3
import time
import uuid
from typing import Any, Dict, List, Optional

from db import connect
from services.b2b_quote_service import _chain_paths, _effective_status, _emit, _load_quote_row


def issue_invoice(
    base_dir: str,
    data_dir: str,
    *,
    quote_id: str,
    actor_user_id: int,
    vat_rate: float = 23.0,
    external_ref: Optional[str] = None,
) -> Dict[str, Any]:
    """Seller issues the (single) invoice for an ACCEPTED, priced quote."""
    quote_id = (quote_id or "").strip()
    actor_user_id = int(actor_user_id)

    row = _load_quote_row(base_dir, quote_id)
    if not row:
        raise LookupError("quote_not_found")
    if actor_user_id != int(row["seller_user_id"]):
        raise PermissionError("not_seller")
    if _effective_status(row) != "ACCEPTED":
        raise ValueError("quote_not_accepted")

    total_net = row.get("total_net")
    try:
        total_net_f = float(total_net) if total_net is not None else 0.0
    except Exception:
        total_net_f = 0.0
    if total_net_f <= 0:
        raise ValueError("quote_not_priced")

    try:
        vat_rate_f = float(vat_rate)
    except Exception:
        raise ValueError("bad_vat_rate")
    if not (0 <= vat_rate_f <= 100):
        raise ValueError("bad_vat_rate")

    external_ref_str = (str(external_ref).strip() or None) if external_ref is not None else None

    amount_net = total_net_f
    vat_amount = round(amount_net * vat_rate_f / 100, 2)
    amount_gross = round(amount_net + vat_amount, 2)
    currency = str(row.get("currency") or "PLN")

    invoice_id = uuid.uuid4().hex
    now = time.time()

    conn = connect(base_dir)
    try:
        cur = conn.cursor()
        cur.execute("SELECT invoice_id FROM invoices WHERE quote_id=?", (quote_id,))
        if cur.fetchone():
            raise ValueError("invoice_exists")
        try:
            cur.execute(
                """INSERT INTO invoices
                 (invoice_id, quote_id, buyer_user_id, seller_user_id,
                      amount_net, vat_rate, vat_amount, amount_gross,
                      currency, external_ref, status, issued_ts, paid_ts, completed_ts)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    invoice_id,
                    quote_id,
                    int(row["buyer_user_id"]),
                    int(row["seller_user_id"]),
                    amount_net,
                    vat_rate_f,
                    vat_amount,
                    amount_gross,
                    currency,
                    external_ref_str,
                    "ISSUED",
                    now,
                    None,
                    None,
                ),
            )
        except sqlite3.IntegrityError:
            # UNIQUE(quote_id) — lost a race with a concurrent issue.
            raise ValueError("invoice_exists")
        conn.commit()
    finally:
        conn.close()

    # Chain payload: process truth only — NO company data, NO external_ref.
    _emit(_chain_paths(data_dir), "INVOICE_ISSUED", {
        "invoice_id": invoice_id,
        "quote_id": quote_id,
        "amount_net": amount_net,
        "vat_rate": vat_rate_f,
        "amount_gross": amount_gross,
        "currency": currency,
    })

    return _load_invoice_row(base_dir, invoice_id) or {}


def confirm_payment(base_dir: str, data_dir: str, *, invoice_id: str, actor_user_id: int) -> Dict[str, Any]:
    """Seller confirms the offline payment arrived. ISSUED -> PAID."""
    row = _seller_action_row(base_dir, invoice_id, actor_user_id, required_status="ISSUED")
    now = time.time()
    conn = connect(base_dir)
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE invoices SET status='PAID', paid_ts=? WHERE invoice_id=?",
            (now, row["invoice_id"]),
        )
        conn.commit()
    finally:
        conn.close()

    _emit(_chain_paths(data_dir), "PAYMENT_CONFIRMED", {
        "invoice_id": row["invoice_id"],
        "quote_id": row["quote_id"],
        "amount_gross": row["amount_gross"],
    })
    return _load_invoice_row(base_dir, row["invoice_id"]) or {}


def complete_order(base_dir: str, data_dir: str, *, invoice_id: str, actor_user_id: int) -> Dict[str, Any]:
    """Seller marks the paid order as fulfilled. PAID -> COMPLETED (terminal)."""
    row = _seller_action_row(base_dir, invoice_id, actor_user_id, required_status="PAID")
    now = time.time()
    conn = connect(base_dir)
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE invoices SET status='COMPLETED', completed_ts=? WHERE invoice_id=?",
            (now, row["invoice_id"]),
        )
        conn.commit()
    finally:
        conn.close()

    _emit(_chain_paths(data_dir), "ORDER_COMPLETED", {
        "invoice_id": row["invoice_id"],
        "quote_id": row["quote_id"],
    })
    return _load_invoice_row(base_dir, row["invoice_id"]) or {}


def get_invoice(base_dir: str, *, invoice_id: str, actor_user_id: int) -> Dict[str, Any]:
    row = _load_invoice_row(base_dir, (invoice_id or "").strip())
    if not row:
        raise LookupError("invoice_not_found")
    actor_user_id = int(actor_user_id)
    if actor_user_id not in (int(row["buyer_user_id"]), int(row["seller_user_id"])):
        raise PermissionError("forbidden")
    return row


def get_invoice_for_quote(base_dir: str, *, quote_id: str, actor_user_id: int) -> Optional[Dict[str, Any]]:
    """Return the invoice for a quote, or None if not yet issued.

    The quote itself must exist and the actor must be a party of it —
    otherwise LookupError / PermissionError, same as get_quote.
    """
    quote = _load_quote_row(base_dir, (quote_id or "").strip())
    if not quote:
        raise LookupError("quote_not_found")
    actor_user_id = int(actor_user_id)
    if actor_user_id not in (int(quote["buyer_user_id"]), int(quote["seller_user_id"])):
        raise PermissionError("forbidden")
    conn = connect(base_dir)
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM invoices WHERE quote_id=?", (quote["quote_id"],))
        row = cur.fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def list_invoices(base_dir: str, user_id: int, limit: int = 100) -> List[Dict[str, Any]]:
    """Return invoices where user is buyer OR seller, newest first."""
    user_id = int(user_id)
    if user_id <= 0:
        return []
    limit = max(1, min(500, int(limit)))
    conn = connect(base_dir)
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT * FROM invoices
               WHERE buyer_user_id=? OR seller_user_id=?
               ORDER BY issued_ts DESC
               LIMIT ?""",
            (user_id, user_id, limit),
        )
        rows = cur.fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


# --- internal helpers ------------------------------------------------------

def _load_invoice_row(base_dir: str, invoice_id: str) -> Optional[Dict[str, Any]]:
    if not invoice_id:
        return None
    conn = connect(base_dir)
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM invoices WHERE invoice_id=?", (invoice_id,))
        row = cur.fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def _seller_action_row(base_dir: str, invoice_id: str, actor_user_id: int, *, required_status: str) -> Dict[str, Any]:
    """Shared guard for seller-only status transitions."""
    row = _load_invoice_row(base_dir, (invoice_id or "").strip())
    if not row:
        raise LookupError("invoice_not_found")
    if int(actor_user_id) != int(row["seller_user_id"]):
        raise PermissionError("not_seller")
    status = str(row.get("status") or "")
    if status != required_status:
        raise ValueError(f"bad_status:{status}")
    return row
