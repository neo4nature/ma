"""F-22: atomowa usługa zakupu marketplace — testy jednostkowe execute_market_purchase.

Nie dotyka HTTP (endpoint market_buy nie istnieje w tym build). Sprawdza:
  - happy path: reserve -> transfer -> sold -> purchase, wszystkie 4 efekty widoczne
  - transfer FAIL: rollback wszystkiego, ZERO efektów, listing zostaje ACTIVE
  - DB record FAIL po udanym transferze: kompensacja (reverse transfer), listing wraca do ACTIVE
  - idempotencja: drugie wywołanie z tym samym purchase_id nie dubluje.

Używamy stub-a transfer_fn (nie realnego _wallet_transfer_internal) — cel to
atomowość samej usługi DB + kontrakt callback-a.
"""
from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest


def _reset_db(tmp_path):
    os.environ["MA_DATA_DIR"] = str(tmp_path / "data")
    os.environ["MA_SECRETS_DIR"] = str(tmp_path / "secrets")
    for mod in ["app", "db", "core.paths"]:
        if mod in sys.modules:
            del sys.modules[mod]
    import db as db_mod
    db_mod.init_db(str(tmp_path))
    return db_mod


def _make_listing(db_mod, base_dir, seller="alice", price=10.0):
    lid = str(uuid.uuid4())
    db_mod.create_market_listing(base_dir, lid, seller, "T", "D", float(price))
    return lid


def _get_status(db_mod, base_dir, listing_id):
    row = db_mod.get_market_listing(base_dir, listing_id)
    return row["status"] if row else None


def _count_purchases(db_mod, base_dir):
    conn = db_mod.connect(base_dir)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM market_purchases")
    n = cur.fetchone()["c"]
    conn.close()
    return n


def test_execute_market_purchase_happy_path(tmp_path):
    db = _reset_db(tmp_path)
    base = str(tmp_path)
    lid = _make_listing(db, base, seller="alice", price=10.0)

    calls = []

    def transfer_ok(sender, receiver, amount, desc):
        calls.append((sender, receiver, amount, desc))
        return {"ok": True, "tx_id": "tx-1", "horizon_receipt_id": "hz-1"}

    pid = str(uuid.uuid4())
    res = db.execute_market_purchase(
        base, pid, lid, buyer="bob", seller="alice",
        amount=10.0, currency="LC", transfer_fn=transfer_ok,
    )
    assert res["ok"] is True
    assert res["idempotent"] is False
    assert res["tx_id"] == "tx-1"
    assert len(calls) == 1
    assert _get_status(db, base, lid) == "SOLD"
    row = db.get_market_listing(base, lid)
    assert row["owner"] == "bob"
    assert _count_purchases(db, base) == 1


def test_execute_market_purchase_transfer_failure_rolls_back(tmp_path):
    db = _reset_db(tmp_path)
    base = str(tmp_path)
    lid = _make_listing(db, base, seller="alice", price=10.0)

    def transfer_fail(sender, receiver, amount, desc):
        return {"ok": False, "reason": "insufficient_funds"}

    pid = str(uuid.uuid4())
    res = db.execute_market_purchase(
        base, pid, lid, buyer="bob", seller="alice",
        amount=10.0, currency="LC", transfer_fn=transfer_fail,
    )
    assert res["ok"] is False
    assert res["reason"] == "insufficient_funds"
    # ZERO efektów częściowych.
    assert _get_status(db, base, lid) == "ACTIVE"
    assert _count_purchases(db, base) == 0


def test_execute_market_purchase_record_failure_compensates(tmp_path, monkeypatch):
    db = _reset_db(tmp_path)
    base = str(tmp_path)
    lid = _make_listing(db, base, seller="alice", price=10.0)

    transfer_log = []

    def transfer_fn(sender, receiver, amount, desc):
        transfer_log.append((sender, receiver, amount, desc))
        return {"ok": True, "tx_id": f"tx-{len(transfer_log)}"}

    # Monkeypatch connect to fail exactly once during the "record" phase (2nd BEGIN).
    original_connect = db.connect
    calls = {"n": 0}

    def flaky_connect(base_dir):
        calls["n"] += 1
        # 1st call = idempotence check (SELECT), 2nd = reserve BEGIN, 3rd = record BEGIN -> fail
        if calls["n"] == 3:
            raise RuntimeError("simulated_db_failure")
        return original_connect(base_dir)

    monkeypatch.setattr(db, "connect", flaky_connect)

    pid = str(uuid.uuid4())
    res = db.execute_market_purchase(
        base, pid, lid, buyer="bob", seller="alice",
        amount=10.0, currency="LC", transfer_fn=transfer_fn,
    )
    monkeypatch.setattr(db, "connect", original_connect)

    assert res["ok"] is False
    # Kompensacja: dwie akcje transfer_fn — forward + reverse.
    assert len(transfer_log) >= 2
    forward, reverse = transfer_log[0], transfer_log[1]
    assert forward[0] == "bob" and forward[1] == "alice"
    assert reverse[0] == "alice" and reverse[1] == "bob"
    assert reverse[2] == forward[2]
    assert "COMPENSATE" in reverse[3]
    # Purchase nie zapisany.
    assert _count_purchases(db, base) == 0
    # Listing wrócił do ACTIVE.
    assert _get_status(db, base, lid) == "ACTIVE"


def test_execute_market_purchase_idempotent(tmp_path):
    db = _reset_db(tmp_path)
    base = str(tmp_path)
    lid = _make_listing(db, base, seller="alice", price=10.0)

    calls = []

    def transfer_ok(sender, receiver, amount, desc):
        calls.append(1)
        return {"ok": True, "tx_id": "tx-1", "horizon_receipt_id": "hz-1"}

    pid = str(uuid.uuid4())
    r1 = db.execute_market_purchase(
        base, pid, lid, buyer="bob", seller="alice",
        amount=10.0, currency="LC", transfer_fn=transfer_ok,
    )
    assert r1["ok"] and not r1["idempotent"]

    # Second call — must NOT double-transfer, NOT insert, return idempotent flag.
    r2 = db.execute_market_purchase(
        base, pid, lid, buyer="bob", seller="alice",
        amount=10.0, currency="LC", transfer_fn=transfer_ok,
    )
    assert r2["ok"] and r2["idempotent"] is True
    assert r2["tx_id"] == "tx-1"
    assert len(calls) == 1
    assert _count_purchases(db, base) == 1
