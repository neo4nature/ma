"""
AI-BEZPIECZEŃSTWO — Strażniczka
Szuka potencjalnych ataków i anomalii.
"""
from typing import Dict, Any


def evaluate_security(tx: Dict[str, Any]) -> Dict[str, Any]:
    amount = float(tx.get("amount") or 0.0)
    description = (tx.get("description") or "").lower()

    if amount > 10000:
        return {
            "name": "AI-Bezpieczeństwo",
            "level": "block",
            "score": 0.1,
            "reason": "Kwota jest zbyt duża jak na domyślne limity bezpieczeństwa.",
        }

    if "hack" in description or "attack" in description:
        return {
            "name": "AI-Bezpieczeństwo",
            "level": "warn",
            "score": 0.4,
            "reason": "Opis wygląda podejrzanie (słowa kluczowe związane z atakiem).",
        }

    return {
        "name": "AI-Bezpieczeństwo",
        "level": "ok",
        "score": 0.9,
        "reason": "Nie wykryto oczywistych sygnałów ataku w tej transakcji.",
    }
