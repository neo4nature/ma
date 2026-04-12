"""
AI-EKONOMIA — Bankier i księgowy
Sprawdza, czy transakcje są realne ekonomicznie.
"""
from typing import Dict, Any


def evaluate_economy(tx: Dict[str, Any]) -> Dict[str, Any]:
    amount = float(tx.get("amount") or 0.0)

    VIRTUAL_BALANCE = 100000.0

    if amount > VIRTUAL_BALANCE:
        return {
            "name": "AI-Ekonomia",
            "level": "block",
            "score": 0.2,
            "reason": "Kwota przekracza założony wirtualny balans portfela.",
        }

    if amount > VIRTUAL_BALANCE * 0.5:
        return {
            "name": "AI-Ekonomia",
            "level": "warn",
            "score": 0.5,
            "reason": "Transakcja jest duża względem dostępnych środków (powyżej 50%).",
        }

    return {
        "name": "AI-Ekonomia",
        "level": "ok",
        "score": 0.92,
        "reason": "Transakcja mieści się w bezpiecznym zakresie wirtualnej ekonomii.",
    }
