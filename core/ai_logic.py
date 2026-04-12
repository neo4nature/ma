"""
AI-LOGIKA — Analityk matematyczny
Sprawdza spójność i sens transakcji.
"""
from typing import Dict, Any


def evaluate_logic(tx: Dict[str, Any]) -> Dict[str, Any]:
    sender = tx.get("sender") or ""
    receiver = tx.get("receiver") or ""
    amount = float(tx.get("amount") or 0.0)

    if amount <= 0:
        return {
            "name": "AI-Logika",
            "level": "block",
            "score": 0.0,
            "reason": "Kwota transakcji musi być dodatnia.",
        }

    if sender.strip() == receiver.strip():
        return {
            "name": "AI-Logika",
            "level": "block",
            "score": 0.1,
            "reason": "Nadawca i odbiorca nie mogą być tą samą stroną.",
        }

    return {
        "name": "AI-Logika",
        "level": "ok",
        "score": 0.95,
        "reason": "Transakcja wygląda logicznie i spójnie na poziomie struktury.",
    }
