
import importlib
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path

from db import create_compute_job, create_user, get_compute_job, get_user_by_username, init_db, set_contrib_slider


def _load_app(tmp_path, worker_token=""):
    os.environ["MA_DATA_DIR"] = str(tmp_path / "data")
    os.environ["MA_SECRETS_DIR"] = str(tmp_path / "secrets")
    os.environ["MA_SIGNER_MODE"] = "SOFTWARE"
    os.environ["MA_WORKER_TICK_TOKEN"] = worker_token
    if "app" in sys.modules:
        del sys.modules["app"]
    import app  # noqa: F401
    return importlib.reload(sys.modules["app"])


def _make_user(base_dir: str, username: str, password: str = "pwx"):
    create_user(base_dir, username, password)
    row = get_user_by_username(base_dir, username)
    return int(row["id"])


def test_worker_tick_requires_token_when_configured(tmp_path, monkeypatch):
    app_mod = _load_app(tmp_path, worker_token="secret-token")
    init_db(app_mod.BASE_DIR)
    worker_id = _make_user(app_mod.BASE_DIR, "worker")
    set_contrib_slider(app_mod.BASE_DIR, worker_id, 50)

    client = app_mod.app.test_client()
    with client.session_transaction() as sess:
        sess["username"] = "worker"

    resp = client.post("/api/compute/worker/tick", json={})
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "worker_auth_invalid"

    resp2 = client.post("/api/compute/worker/tick", json={}, headers={"X-Worker-Token": "secret-token"})
    assert resp2.status_code == 200
    assert resp2.get_json()["ok"] is True


def test_cancel_queued_job_refunds_once(tmp_path, monkeypatch):
    app_mod = _load_app(tmp_path)
    init_db(app_mod.BASE_DIR)
    _make_user(app_mod.BASE_DIR, "owner")
    calls = []

    def fake_transfer(sender, receiver, amount, title, allow_firmware_for_sender=False):
        calls.append((sender, receiver, amount, title))
        return {"ok": True, "tx": {"id": "tx-refund-1"}}

    monkeypatch.setattr(app_mod, "_wallet_transfer_internal", fake_transfer)

    now = time.time()
    create_compute_job(app_mod.BASE_DIR, {
        "id": "job-q-1",
        "owner": "owner",
        "kind": "render_stub",
        "src_relpath": "uploads/in.bin",
        "status": "QUEUED",
        "created_at": now,
        "updated_at": now,
        "cost_units": 1.0,
        "price_multiplier": 1.0,
        "pricing_inputs_json": "{}",
        "escrow_amount": 1.0,
        "escrow_status": "HELD",
        "escrow_tx_id": "escrow-1",
        "result_relpath": None,
    })

    client = app_mod.app.test_client()
    with client.session_transaction() as sess:
        sess["username"] = "owner"

    resp = client.post("/api/compute/job/cancel", json={"job_id": "job-q-1"})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["canceled"] is True
    assert body["status"] == "CANCELED"
    assert body["settlement"]["ok"] is True
    assert len(calls) == 1

    # calling cancel again must not cause a second refund
    resp2 = client.post("/api/compute/job/cancel", json={"job_id": "job-q-1"})
    body2 = resp2.get_json()
    assert body2["canceled"] is False
    assert len(calls) == 1

    fresh = get_compute_job(app_mod.BASE_DIR, "job-q-1")
    assert fresh["escrow_status"] == "REFUNDED"


def test_worker_tick_cancel_during_exec_refunds_once(tmp_path, monkeypatch):
    app_mod = _load_app(tmp_path)
    init_db(app_mod.BASE_DIR)
    _make_user(app_mod.BASE_DIR, "owner")
    worker_id = _make_user(app_mod.BASE_DIR, "worker")
    set_contrib_slider(app_mod.BASE_DIR, worker_id, 50)

    calls = []

    def fake_transfer(sender, receiver, amount, title, allow_firmware_for_sender=False):
        calls.append((sender, receiver, amount, title))
        return {"ok": True, "tx": {"id": "tx-" + str(len(calls))}}

    def fake_execute(job, data_dir):
        # simulate owner cancel arriving during execution
        from db import cancel_compute_job
        cancel_compute_job(app_mod.BASE_DIR, job_id=str(job["id"]), owner=str(job["owner"]))
        rel = "compute_results/test.out"
        out = Path(data_dir) / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(b"x")
        return rel, "abc123"

    monkeypatch.setattr(app_mod, "_wallet_transfer_internal", fake_transfer)
    monkeypatch.setattr(app_mod, "_execute_compute_job_local", fake_execute)

    now = time.time()
    create_compute_job(app_mod.BASE_DIR, {
        "id": "job-w-1",
        "owner": "owner",
        "kind": "render_stub",
        "src_relpath": "uploads/in.bin",
        "status": "QUEUED",
        "created_at": now,
        "updated_at": now,
        "cost_units": 2.0,
        "price_multiplier": 1.0,
        "pricing_inputs_json": "{}",
        "escrow_amount": 2.0,
        "escrow_status": "HELD",
        "escrow_tx_id": "escrow-2",
        "result_relpath": None,
    })

    client = app_mod.app.test_client()
    with client.session_transaction() as sess:
        sess["username"] = "worker"

    resp = client.post("/api/compute/worker/tick", json={})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["canceled"] is True
    assert body["settlement"]["ok"] is True
    assert len(calls) == 1

    fresh = get_compute_job(app_mod.BASE_DIR, "job-w-1")
    assert fresh["status"] == "CANCELED"
    assert fresh["escrow_status"] == "REFUNDED"
