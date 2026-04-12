"""
AI-SPÓJNOŚĆ — Filozof i harmonizator
Pilnuje, by system nie zszedł z drogi.
"""
from typing import Dict, Any


def evaluate_consistency(tx: Dict[str, Any]) -> Dict[str, Any]:
    description = (tx.get("description") or "").lower()

    if "przymus" in description or "muszę" in description:
        return {
            "name": "AI-Spójność",
            "level": "warn",
            "score": 0.5,
            "reason": "Opis zawiera element przymusu – warto upewnić się, że intencja jest zgodna z wartościami systemu.",
        }

    return {
        "name": "AI-Spójność",
        "level": "ok",
        "score": 0.95,
        "reason": "Transakcja jest spójna z domyślną ścieżką wartości MA (model 0.1).",
    }
