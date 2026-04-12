from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class Transaction:
    sender: str
    receiver: str
    amount: float
    description: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Transaction":
        return cls(
            sender=str(data.get("sender") or ""),
            receiver=str(data.get("receiver") or ""),
            amount=float(data.get("amount") or 0.0),
            description=str(data.get("description") or ""),
        )
