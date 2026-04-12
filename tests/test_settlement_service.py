from services.settlement_service import settle_compute_job, wallet_transfer_internal


def test_settle_compute_job_done_with_treasury_cut():
    transfers = []
    settlements = []

    def _wallet(sender, receiver, amount, description):
        transfers.append((sender, receiver, amount, description))
        return {"ok": True, "tx": {"id": f"tx-{len(transfers)}"}}

    res = settle_compute_job(
        base_dir="/tmp/base",
        job={"id": "job1", "owner": "neo", "kind": "render_stub", "escrow_amount": 10.0, "escrow_status": "HELD"},
        outcome_status="DONE",
        escrow_account="escrow",
        treasury_account="treasury",
        treasury_cut=0.1,
        get_compute_job=lambda base, jid: {"id": jid, "owner": "neo", "kind": "render_stub", "escrow_amount": 10.0, "escrow_status": "HELD"},
        set_compute_job_settlement=lambda base_dir, **kw: settlements.append(kw),
        wallet_transfer_internal=_wallet,
        refund_compute_job_escrow_once=lambda *a, **k: {"ok": False},
    )

    assert res["type"] == "PAYOUT"
    assert transfers[0] == ("escrow", "treasury", 1.0, "COMPUTE_FEE:job1")
    assert transfers[1] == ("escrow", "neo", 9.0, "COMPUTE_PAYOUT:job1:render_stub")
    assert settlements and settlements[0]["escrow_status"] == "PAID"


def test_settle_compute_job_failed_refunds():
    seen = {}
    def _refund(job_id, reason):
        seen["job_id"] = job_id
        seen["reason"] = reason
        return {"ok": True}

    res = settle_compute_job(
        base_dir="/tmp/base",
        job={"id": "job2", "owner": "neo", "kind": "render_stub", "escrow_amount": 10.0, "escrow_status": "HELD"},
        outcome_status="FAILED",
        escrow_account="escrow",
        treasury_account="treasury",
        treasury_cut=0.1,
        get_compute_job=lambda base, jid: {"id": jid, "owner": "neo", "kind": "render_stub", "escrow_amount": 10.0, "escrow_status": "HELD"},
        set_compute_job_settlement=lambda *a, **k: None,
        wallet_transfer_internal=lambda *a, **k: {"ok": True, "tx": {"id": "unused"}},
        refund_compute_job_escrow_once=_refund,
    )

    assert res["type"] == "REFUND"
    assert seen == {"job_id": "job2", "reason": "failed"}


def test_wallet_transfer_internal_blocks_disallowed_transaction():
    applied = []
    res = wallet_transfer_internal(
        sender="neo",
        receiver="escrow",
        amount=2.5,
        description="TEST",
        load_state=lambda: {},
        ensure_account=lambda *a, **k: None,
        ensure_user_wallet_keypair=lambda *a, **k: None,
        wallet_keys_dir="/tmp/keys",
        evaluate_transaction=lambda tx, st: ({"allowed": False}, {"ai": "blocked"}),
        apply_transaction=lambda st, tx, decision, signature=None: applied.append((tx, decision, signature)) or st,
        current_user=lambda: "neo",
        signer_mode="SOFTWARE",
        sign_transaction_via_firmware=lambda *a, **k: {"tx_sig_b64": "sig"},
        sign_transaction=lambda *a, **k: "sig-soft",
        sign_horizon_receipt=lambda *a, **k: {"tx_hash": "hash"},
        rounds_state_file="/tmp/rstate.json",
        rounds_file="/tmp/rounds.jsonl",
        horizon_master_keys_dir="/tmp/horizon",
        add_event_to_round=lambda *a, **k: None,
    )
    assert res["ok"] is False
    assert applied and applied[0][2] is None


def test_settle_compute_job_clamps_treasury_cut_and_skips_already_paid():
    transfers = []
    settlements = []

    def _wallet(sender, receiver, amount, description):
        transfers.append((sender, receiver, amount, description))
        return {"ok": True, "tx": {"id": f"tx-{len(transfers)}"}}

    res = settle_compute_job(
        base_dir="/tmp/base",
        job={"id": "job3", "owner": "neo", "kind": "render_stub", "escrow_amount": 10.0, "escrow_status": "HELD"},
        outcome_status="DONE",
        escrow_account="escrow",
        treasury_account="treasury",
        treasury_cut=0.9,
        get_compute_job=lambda base, jid: {"id": jid, "owner": "neo", "kind": "render_stub", "escrow_amount": 10.0, "escrow_status": "HELD"},
        set_compute_job_settlement=lambda base_dir, **kw: settlements.append(kw),
        wallet_transfer_internal=_wallet,
        refund_compute_job_escrow_once=lambda *a, **k: {"ok": False},
    )

    assert res["type"] == "PAYOUT"
    assert transfers[0][2] == 5.0
    assert transfers[1][2] == 5.0
    assert settlements and settlements[0]["escrow_status"] == "PAID"

    transfers.clear()
    res2 = settle_compute_job(
        base_dir="/tmp/base",
        job={"id": "job3", "owner": "neo", "kind": "render_stub", "escrow_amount": 10.0, "escrow_status": "PAID"},
        outcome_status="DONE",
        escrow_account="escrow",
        treasury_account="treasury",
        treasury_cut=0.1,
        get_compute_job=lambda base, jid: {"id": jid, "owner": "neo", "kind": "render_stub", "escrow_amount": 10.0, "escrow_status": "PAID"},
        set_compute_job_settlement=lambda base_dir, **kw: settlements.append(kw),
        wallet_transfer_internal=_wallet,
        refund_compute_job_escrow_once=lambda *a, **k: {"ok": False},
    )
    assert res2 is None
    assert transfers == []


def test_settle_compute_job_does_not_reduce_payout_when_fee_transfer_fails():
    transfers = []

    def _wallet(sender, receiver, amount, description):
        transfers.append((sender, receiver, amount, description))
        if receiver == "treasury":
            return {"ok": False, "tx": {"id": "fee-fail"}}
        return {"ok": True, "tx": {"id": "payout-ok"}}

    res = settle_compute_job(
        base_dir="/tmp/base",
        job={"id": "job4", "owner": "neo", "kind": "render_stub", "escrow_amount": 10.0, "escrow_status": "HELD"},
        outcome_status="DONE",
        escrow_account="escrow",
        treasury_account="treasury",
        treasury_cut=0.1,
        get_compute_job=lambda base, jid: {"id": jid, "owner": "neo", "kind": "render_stub", "escrow_amount": 10.0, "escrow_status": "HELD"},
        set_compute_job_settlement=lambda *a, **k: None,
        wallet_transfer_internal=_wallet,
        refund_compute_job_escrow_once=lambda *a, **k: {"ok": False},
    )

    assert transfers[0] == ("escrow", "treasury", 1.0, "COMPUTE_FEE:job4")
    assert transfers[1] == ("escrow", "neo", 10.0, "COMPUTE_PAYOUT:job4:render_stub")
    assert res["ok"] is True
    assert res["fee_ok"] is False


def test_settle_compute_job_reverts_fee_when_payout_fails_after_fee_success():
    transfers = []
    settlements = []

    def _wallet(sender, receiver, amount, description):
        transfers.append((sender, receiver, amount, description))
        if description.startswith("COMPUTE_PAYOUT"):
            return {"ok": False, "tx": {"id": "payout-fail"}}
        if description.startswith("COMPUTE_FEE_REVERT"):
            return {"ok": True, "tx": {"id": "fee-revert-ok"}}
        return {"ok": True, "tx": {"id": f"tx-{len(transfers)}"}}

    res = settle_compute_job(
        base_dir="/tmp/base",
        job={"id": "job5", "owner": "neo", "kind": "render_stub", "escrow_amount": 10.0, "escrow_status": "HELD"},
        outcome_status="DONE",
        escrow_account="escrow",
        treasury_account="treasury",
        treasury_cut=0.1,
        get_compute_job=lambda base, jid: {"id": jid, "owner": "neo", "kind": "render_stub", "escrow_amount": 10.0, "escrow_status": "HELD"},
        set_compute_job_settlement=lambda base_dir, **kw: settlements.append(kw),
        wallet_transfer_internal=_wallet,
        refund_compute_job_escrow_once=lambda *a, **k: {"ok": False},
    )

    assert transfers[0] == ("escrow", "treasury", 1.0, "COMPUTE_FEE:job5")
    assert transfers[1] == ("escrow", "neo", 9.0, "COMPUTE_PAYOUT:job5:render_stub")
    assert transfers[2] == ("treasury", "escrow", 1.0, "COMPUTE_FEE_REVERT:job5")
    assert res["ok"] is False
    assert res["fee_ok"] is True
    assert res["fee_reverted"] is True
    assert settlements == []


def test_settle_compute_job_reports_failed_fee_revert_when_compensation_fails():
    transfers = []

    def _wallet(sender, receiver, amount, description):
        transfers.append((sender, receiver, amount, description))
        if description.startswith("COMPUTE_PAYOUT"):
            return {"ok": False, "tx": {"id": "payout-fail"}}
        if description.startswith("COMPUTE_FEE_REVERT"):
            return {"ok": False, "tx": {"id": "fee-revert-fail"}}
        return {"ok": True, "tx": {"id": f"tx-{len(transfers)}"}}

    res = settle_compute_job(
        base_dir="/tmp/base",
        job={"id": "job6", "owner": "neo", "kind": "render_stub", "escrow_amount": 10.0, "escrow_status": "HELD"},
        outcome_status="DONE",
        escrow_account="escrow",
        treasury_account="treasury",
        treasury_cut=0.1,
        get_compute_job=lambda base, jid: {"id": jid, "owner": "neo", "kind": "render_stub", "escrow_amount": 10.0, "escrow_status": "HELD"},
        set_compute_job_settlement=lambda *a, **k: None,
        wallet_transfer_internal=_wallet,
        refund_compute_job_escrow_once=lambda *a, **k: {"ok": False},
    )

    assert res["ok"] is False
    assert res["fee_ok"] is True
    assert res["fee_reverted"] is False
    assert res["fee_revert_tx_id"] == "fee-revert-fail"
