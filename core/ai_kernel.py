"""
AI Kernel – orkiestracja pięciu AI.
"""
from typing import Dict, Any

from .ai_logic import evaluate_logic
from .ai_security import evaluate_security
from .ai_economy import evaluate_economy
from .ai_optimization import evaluate_optimization
from .ai_consistency import evaluate_consistency


def run_all_ai(tx: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        "logic": evaluate_logic(tx),
        "security": evaluate_security(tx),
        "economy": evaluate_economy(tx),
        "optimization": evaluate_optimization(tx),
        "consistency": evaluate_consistency(tx),
    }
