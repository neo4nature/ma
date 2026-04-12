"""
Horyzont – warstwa ponad pięcioma AI (MA v0.1).

Zasada:
- 5 modułów ocenia transakcję (OK/WARN/BLOCK)
- Horyzont jest minimalnym strażnikiem: decyzja ALLOW/BLOCK + status OK/WARN/BLOCK
- Dodatkowo Horyzont ma prawo egzekwować twarde reguły systemowe (np. brak środków).
"""
from __future__ import annotations

from typing import Dict, Any, Tuple

from .ai_kernel import run_all_ai


def _has_sufficient_funds(state: Dict[str, Any] | None, sender: str, amount: float) -> bool:
    if state is None:
        return True  # bez stanu nie umiemy policzyć – nie blokujemy w v0.1
    accounts = state.get("accounts") or {}
    try:
        bal = float(accounts.get(sender, 0.0))
    except Exception:
        bal = 0.0
    return bal >= amount


def evaluate_transaction(tx: Dict[str, Any], state: Dict[str, Any] | None = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    verdicts = run_all_ai(tx)

    has_block = any(v.get("level") == "block" for v in verdicts.values())
    has_warn = any(v.get("level") == "warn" for v in verdicts.values())

    # twarda reguła księgowa: nie pozwól zejść poniżej zera
    sender = (tx.get("sender") or "").strip()
    amount = float(tx.get("amount") or 0.0)
    if amount > 0 and sender and not _has_sufficient_funds(state, sender, amount):
        decision = {
            "allowed": False,
            "status": "BLOCK",
            "reason": "Brak środków: saldo nadawcy jest mniejsze niż kwota transakcji.",
        }
        return decision, verdicts

    if has_block:
        decision = {
            "allowed": False,
            "status": "BLOCK",
            "reason": "Co najmniej jeden moduł AI zablokował transakcję (v0.1).",
        }
    elif has_warn:
        decision = {
            "allowed": True,
            "status": "WARN",
            "reason": "Część modułów zgłosiła ostrzeżenia. Podpis dozwolony, ale z podniesioną czujnością.",
        }
    else:
        decision = {
            "allowed": True,
            "status": "OK",
            "reason": "Wszystkie moduły AI zaakceptowały transakcję w wersji 0.1.",
        }

    return decision, verdicts
