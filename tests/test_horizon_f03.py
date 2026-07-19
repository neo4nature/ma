"""F-03: Horyzont weryfikuje tożsamość nadawcy i (opcjonalnie) podpis transakcji.

Audyt A01/A04: evaluate_transaction sprawdzał tylko werdykty AI i saldo.
Nie weryfikował, czy sender == zalogowany użytkownik ani czy podpis się zgadza.
Zagrożenie: przy user-facing endpointach przelewu (comm_send_money) wzorzec
staje się "przelej z cudzego konta".

Reguły fail-closed:
- amount > 0 i sender niepusty  =>  wymagany (session_user == sender)
  LUB authorized_by == "escrow" (systemowy)
- gdy tx_sig_b64 podane => musi się weryfikować kluczem sendera
- amount == 0 => zachowanie bez zmian (eventy informacyjne, np. COMPUTE_RESULT)
"""

from __future__ import annotations

import importlib
import os
import sys


def _fresh_env(tmp_path):
    """Set isolated MA dirs and reload wallet + horizon modules."""
    os.environ["MA_DATA_DIR"] = str(tmp_path / "data")
    os.environ["MA_SECRETS_DIR"] = str(tmp_path / "secrets")
    for mod in ["core.horizon", "wallet.key_manager", "wallet.tx_signer", "wallet.user_keys", "core.paths"]:
        if mod in sys.modules:
            del sys.modules[mod]
    import core.horizon  # noqa: F401
    return importlib.reload(sys.modules["core.horizon"])


def _state_with_balance(sender: str, balance: float) -> dict:
    return {"accounts": {sender: balance}}


# ---------------------------------------------------------------------------
# (a) sender != session_user  =>  BLOCK
# ---------------------------------------------------------------------------
def test_f03_blocks_when_sender_differs_from_session(tmp_path):
    horizon = _fresh_env(tmp_path)
    tx = {"id": "t1", "sender": "alice", "receiver": "bob", "amount": 5.0, "timestamp": 0}
    st = _state_with_balance("alice", 1000.0)
    decision, _ = horizon.evaluate_transaction(tx, st, session_user="mallory")
    assert decision["allowed"] is False
    assert decision["status"] == "BLOCK"
    assert "nadawca" in decision["reason"].lower()


# ---------------------------------------------------------------------------
# (b) sender == session_user  =>  identity rule passes
# ---------------------------------------------------------------------------
def test_f03_allows_when_sender_matches_session(tmp_path):
    horizon = _fresh_env(tmp_path)
    tx = {"id": "t2", "sender": "alice", "receiver": "bob", "amount": 5.0, "timestamp": 0}
    st = _state_with_balance("alice", 1000.0)
    decision, _ = horizon.evaluate_transaction(tx, st, session_user="alice")
    assert decision["allowed"] is True, decision


# ---------------------------------------------------------------------------
# (c) authorized_by="escrow"  =>  identity rule passes without session
# ---------------------------------------------------------------------------
def test_f03_allows_systemic_escrow_without_session(tmp_path):
    horizon = _fresh_env(tmp_path)
    tx = {"id": "t3", "sender": "escrow_account", "receiver": "neo", "amount": 3.0, "timestamp": 0}
    st = _state_with_balance("escrow_account", 100.0)
    decision, _ = horizon.evaluate_transaction(tx, st, authorized_by="escrow")
    assert decision["allowed"] is True, decision


# ---------------------------------------------------------------------------
# (d) legacy call: amount>0, brak kontekstu  =>  BLOCK (fail-closed)
# ---------------------------------------------------------------------------
def test_f03_blocks_legacy_call_without_context(tmp_path):
    horizon = _fresh_env(tmp_path)
    tx = {"id": "t4", "sender": "alice", "receiver": "bob", "amount": 5.0, "timestamp": 0}
    st = _state_with_balance("alice", 1000.0)
    decision, _ = horizon.evaluate_transaction(tx, st)
    assert decision["allowed"] is False
    assert decision["status"] == "BLOCK"


# ---------------------------------------------------------------------------
# (e) tx_sig_b64 błędny  =>  BLOCK
# ---------------------------------------------------------------------------
def test_f03_blocks_when_signature_invalid(tmp_path):
    horizon = _fresh_env(tmp_path)
    from wallet.user_keys import generate_user_keypair
    generate_user_keypair(str(tmp_path), "alice")

    tx = {"id": "t5", "sender": "alice", "receiver": "bob", "amount": 5.0, "timestamp": 0}
    st = _state_with_balance("alice", 1000.0)
    bogus = "AAAA" + "BBBB" * 16
    decision, _ = horizon.evaluate_transaction(
        tx, st, session_user="alice", tx_sig_b64=bogus,
    )
    assert decision["allowed"] is False
    assert decision["status"] == "BLOCK"
    assert "podpis" in decision["reason"].lower()


# ---------------------------------------------------------------------------
# (f) tx_sig_b64 poprawny  =>  przechodzi
# ---------------------------------------------------------------------------
def test_f03_allows_valid_signature(tmp_path):
    horizon = _fresh_env(tmp_path)
    from wallet.user_keys import generate_user_keypair
    from wallet.tx_signer import sign_transaction
    generate_user_keypair(str(tmp_path), "alice")

    tx = {"id": "t6", "sender": "alice", "receiver": "bob", "amount": 5.0, "timestamp": 0}
    sig = sign_transaction(tx, "alice")
    st = _state_with_balance("alice", 1000.0)
    decision, _ = horizon.evaluate_transaction(
        tx, st, session_user="alice", tx_sig_b64=sig,
    )
    assert decision["allowed"] is True, decision


# ---------------------------------------------------------------------------
# (g) amount == 0  =>  brak reguły tożsamości (COMPUTE_RESULT itp.)
# ---------------------------------------------------------------------------
def test_f03_zero_amount_bypasses_identity_rule(tmp_path):
    horizon = _fresh_env(tmp_path)
    tx = {"id": "t7", "sender": "alice", "receiver": "bob", "amount": 0.0, "timestamp": 0}
    decision, _ = horizon.evaluate_transaction(tx, None)
    reason = (decision.get("reason") or "").lower()
    assert "nadawca" not in reason and "sesji" not in reason and "podpis" not in reason, decision
