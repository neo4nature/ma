from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass
class MessageDecision:
    status: str  # ALLOWED / BLOCKED
    reason: str
    meta: Dict


def evaluate_message(sender: str, receiver: str, body: str, rate_state: Dict) -> Tuple[MessageDecision, Dict]:
    """
    Minimal 'Horyzont' for communicator:
    - metadata-only guards: length, empties, rate limit, spam-repeat hash.
    - no 'opinions' – only TAK/NIE + reason.
    """
    now = time.time()
    body = body or ""
    length = len(body)

    # hard limits
    if length == 0:
        return MessageDecision("BLOCKED", "empty", {"len": 0}), rate_state
    if length > 2000:
        return MessageDecision("BLOCKED", "too_long", {"len": length}), rate_state

    # sender bucket
    s = rate_state.setdefault(sender, {"last_ts": 0.0, "burst": 0, "last_hash": ""})
    dt = now - float(s.get("last_ts", 0.0))
    if dt < 2.0:
        s["burst"] = int(s.get("burst", 0)) + 1
    else:
        s["burst"] = 0

    if s["burst"] >= 5:
        s["last_ts"] = now
        rate_state[sender] = s
        return MessageDecision("BLOCKED", "rate_limit", {"burst": s["burst"], "dt": dt}), rate_state

    h = hashlib.sha256(body.encode("utf-8")).hexdigest()
    if h == s.get("last_hash") and dt < 10.0:
        s["last_ts"] = now
        rate_state[sender] = s
        return MessageDecision("BLOCKED", "repeat_spam", {"dt": dt}), rate_state

    s["last_ts"] = now
    s["last_hash"] = h
    rate_state[sender] = s

    return MessageDecision("ALLOWED", "ok", {"len": length}), rate_state
