"""Settlement and internal wallet-transfer helpers extracted from app.py."""

from __future__ import annotations

import time
import uuid
from pathlib import Path


def wallet_transfer_internal(
    *,
    sender: str,
    receiver: str,
    amount: float,
    description: str,
    allow_firmware_for_sender: bool = False,
    load_state,
    ensure_account,
    ensure_user_wallet_keypair,
    wallet_keys_dir,
    evaluate_transaction,
    apply_transaction,
    current_user,
    signer_mode: str,
    sign_transaction_via_firmware,
    sign_transaction,
    sign_horizon_receipt,
    rounds_state_file,
    rounds_file,
    horizon_master_keys_dir,
    add_event_to_round,
):
    """Internal LifeCoin transfer used by compute escrow/settlement.

    - Uses Horyzont evaluation (incl. sufficient funds).
    - Signs with firmware only when explicitly allowed and the sender is the current user.
    - Otherwise signs with software keys (prototype).
    Returns a dict with: ok, decision, tx, tx_sig_b64, horizon_receipt.
    """
    sender = (sender or "").strip()
    receiver = (receiver or "").strip()
    amount = float(amount or 0.0)

    st = load_state()
    ensure_account(sender, initial=0.0)
    ensure_account(receiver, initial=0.0)
    try:
        ensure_user_wallet_keypair(sender, Path(wallet_keys_dir))
        ensure_user_wallet_keypair(receiver, Path(wallet_keys_dir))
    except Exception:
        pass

    tx = {
        "id": str(uuid.uuid4()),
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "description": (description or "").strip(),
        "timestamp": time.time(),
    }

    decision, verdicts = evaluate_transaction(tx, st)
    if not decision.get("allowed"):
        apply_transaction(st, tx, decision, signature=None)
        return {"ok": False, "decision": decision, "verdicts": verdicts, "tx": tx, "tx_sig_b64": None, "horizon_receipt": None}

    tx_sig_b64 = None
    firmware_meta = None

    if allow_firmware_for_sender and signer_mode == 'FIRMWARE' and sender == (current_user() or ""):
        st.setdefault("meta", {}).setdefault("sign_counters", {})
        last = int(st["meta"]["sign_counters"].get(sender, 0))
        nxt = last + 1
        st["meta"]["sign_counters"][sender] = nxt
        firmware_meta = {"counter": nxt}
        try:
            tx_sig_b64 = sign_transaction_via_firmware(tx, sender, meta=firmware_meta).get('tx_sig_b64')
        except Exception:
            tx_sig_b64 = sign_transaction(tx, sender)
    else:
        tx_sig_b64 = sign_transaction(tx, sender)

    horizon_receipt = None
    try:
        horizon_receipt = sign_horizon_receipt(tx, Path(horizon_master_keys_dir))
    except Exception:
        horizon_receipt = None

    try:
        add_event_to_round(
            Path(rounds_state_file),
            Path(rounds_file),
            Path(horizon_master_keys_dir),
            {
                "type": "TX",
                "tx_id": tx.get("id"),
                "tx_hash": (horizon_receipt or {}).get("tx_hash"),
                "sender": sender,
                "receiver": receiver,
                "amount": amount,
                "timestamp": tx.get("timestamp"),
                "desc": tx.get("description"),
            },
        )
    except Exception:
        pass

    st = apply_transaction(st, tx, decision, signature=tx_sig_b64)

    return {
        "ok": True,
        "decision": decision,
        "verdicts": verdicts,
        "tx": tx,
        "tx_sig_b64": tx_sig_b64,
        "horizon_receipt": horizon_receipt,
        "firmware_meta": firmware_meta,
    }


def settle_compute_job(
    *,
    base_dir: str,
    job: dict,
    outcome_status: str,
    escrow_account: str,
    treasury_account: str,
    treasury_cut: float,
    get_compute_job,
    set_compute_job_settlement,
    wallet_transfer_internal,
    refund_compute_job_escrow_once,
):
    """Finalize payout/refund for a compute job while preserving current behavior."""
    fresh = get_compute_job(base_dir, str(job.get("id"))) or {}
    escrow_amount = float(fresh.get("escrow_amount") or job.get("escrow_amount") or job.get("cost_units") or 0.0)
    escrow_status = str(fresh.get("escrow_status") or job.get("escrow_status") or "NONE").upper()
    if escrow_amount <= 0 or escrow_status in ("PAID", "REFUNDED"):
        return None

    if outcome_status == "DONE":
        payout = float(escrow_amount)
        cut = float(treasury_cut or 0.0)
        cut = max(0.0, min(0.5, cut))
        fee_tx = None
        cut_amt = payout * cut if cut > 0 else 0.0
        if cut > 0:
            fee_tx = wallet_transfer_internal(
                escrow_account,
                treasury_account,
                cut_amt,
                f"COMPUTE_FEE:{job.get('id')}",
            )
            if fee_tx.get("ok"):
                payout = max(0.0, payout - cut_amt)
        pay = wallet_transfer_internal(
            escrow_account,
            str(job.get("owner") or ""),
            payout,
            f"COMPUTE_PAYOUT:{job.get('id')}:{job.get('kind')}",
        )
        fee_revert_tx = None
        if not pay.get("ok") and cut > 0 and (fee_tx or {}).get("ok"):
            try:
                fee_revert_tx = wallet_transfer_internal(
                    treasury_account,
                    escrow_account,
                    cut_amt,
                    f"COMPUTE_FEE_REVERT:{job.get('id')}",
                )
            except Exception:
                fee_revert_tx = {"ok": False, "tx": None}
        if pay.get("ok"):
            set_compute_job_settlement(
                base_dir,
                job_id=str(job.get("id")),
                escrow_status="PAID",
                payout_tx_id=(pay.get("tx") or {}).get("id"),
            )
        return {
            "type": "PAYOUT",
            "ok": bool(pay.get("ok")),
            "tx_id": (pay.get("tx") or {}).get("id"),
            "fee_ok": None if cut <= 0 else bool((fee_tx or {}).get("ok")),
            "fee_tx_id": (fee_tx.get("tx") or {}).get("id") if fee_tx else None,
            "fee_reverted": None if fee_revert_tx is None else bool((fee_revert_tx or {}).get("ok")),
            "fee_revert_tx_id": (fee_revert_tx.get("tx") or {}).get("id") if fee_revert_tx else None,
        }

    settlement = refund_compute_job_escrow_once(str(job.get("id")), reason="failed")
    settlement["type"] = "REFUND"
    return settlement
