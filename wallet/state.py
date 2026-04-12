"""
Soft-wallet state dla MA v0.1
Przechowuje lokalne salda i historię transakcji w jednym pliku JSON.
"""
import os
import json
from typing import Dict, Any

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.getenv("MA_DATA_DIR") or os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

STATE_FILE = os.path.join(DATA_DIR, "wallet_state.json")

DEFAULT_STATE = {
    "accounts": {
        "Neo": 1000.0,
        "Lira": 1000.0,
    },
    "tx_history": [],
    "meta": {
        "sign_counters": {}
    },
}


def load_state() -> Dict[str, Any]:
    if not os.path.exists(STATE_FILE):
        return json.loads(json.dumps(DEFAULT_STATE))
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if "accounts" not in data:
                data["accounts"] = {}
            if "tx_history" not in data:
                data["tx_history"] = []
            if "meta" not in data:
                data["meta"] = {"sign_counters": {}}
            if "sign_counters" not in data.get("meta", {}):
                data.setdefault("meta", {})["sign_counters"] = {}
            return data
    except Exception:
        return json.loads(json.dumps(DEFAULT_STATE))


def save_state(state: Dict[str, Any]) -> None:
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)



def ensure_account(username: str, initial: float = 1000.0) -> Dict[str, Any]:
    """Ensure an account exists in state with an initial balance (prototype)."""
    state = load_state()
    uname = (username or "").strip()
    if not uname:
        return state
    if "accounts" not in state:
        state["accounts"] = {}
    if uname not in state["accounts"]:
        state["accounts"][uname] = float(initial)
        save_state(state)
    return state

def apply_transaction(state: Dict[str, Any], tx: Dict[str, Any], decision: Dict[str, Any], signature: str | None):
    # ensure basic structure
    if "accounts" not in state:
        state["accounts"] = {}
    if "tx_history" not in state:
        state["tx_history"] = []

    sender = tx.get("sender") or ""
    receiver = tx.get("receiver") or ""
    amount = float(tx.get("amount") or 0.0)

    # make sure accounts exist
    if sender and sender not in state["accounts"]:
        state["accounts"][sender] = 0.0
    if receiver and receiver not in state["accounts"]:
        state["accounts"][receiver] = 0.0

    # only modify balances if decyzja pozwala na podpis
    if decision.get("allowed") and decision.get("status") != "BLOCK" and amount > 0:
        state["accounts"][sender] = state["accounts"].get(sender, 0.0) - amount
        state["accounts"][receiver] = state["accounts"].get(receiver, 0.0) + amount

    # append to history (we also zapisujemy zablokowane transakcje)
    entry = {
        "id": tx.get("id"),
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "description": tx.get("description") or "",
        "timestamp": tx.get("timestamp"),
        "status": "SIGNED" if decision.get("allowed") else "BLOCKED",
        "allowed": bool(decision.get("allowed")),
        "decision_status": decision.get("status"),
        "signature": signature,
    }
    state["tx_history"].append(entry)

    # ograniczamy historię do ostatnich 200 wpisów
    if len(state["tx_history"]) > 200:
        state["tx_history"] = state["tx_history"][-200:]

    save_state(state)
    return state
