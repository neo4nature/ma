"""
AI-OPTYMALIZACJA — Inżynier wydajności
Pilnuje energii, obciążenia i kosztów.
"""
from typing import Dict, Any


def evaluate_optimization(tx: Dict[str, Any]) -> Dict[str, Any]:
    amount = float(tx.get("amount") or 0.0)

    if 0 < amount < 0.01:
        return {
            "name": "AI-Optymalizacja",
            "level": "warn",
            "score": 0.6,
            "reason": "Kwota jest bardzo mała – koszt energetyczny może być względnie wysoki.",
        }

    return {
        "name": "AI-Optymalizacja",
        "level": "ok",
        "score": 0.9,
        "reason": "Transakcja wygląda rozsądnie pod kątem obciążenia systemu (model 0.1).",
    }
