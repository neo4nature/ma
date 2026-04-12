from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from core.horizon_signer import ensure_horizon_master_keypair
from core.event_chain import append_event
from cryptography.hazmat.primitives import serialization


def _load_json(path: Path, default: Dict[str, Any]) -> Dict[str, Any]:
    try:
        if path.exists():
            with path.open("r", encoding="utf-8") as f:
                obj = json.load(f)
                if isinstance(obj, dict):
                    return obj
    except Exception:
        pass
    return default


def _save_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _sign_round_hash(round_hash: str, keys_dir: Path) -> Dict[str, str]:
    priv_pem, pub_pem = ensure_horizon_master_keypair(keys_dir)
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    sig = priv.sign(round_hash.encode("ascii"))
    import base64

    return {
        "round_hash": round_hash,
        "horizon_sig_b64": base64.b64encode(sig).decode("ascii"),
        "horizon_pub_pem": pub_pem.decode("utf-8", errors="ignore"),
    }


def add_event(
    event: Dict[str, Any],
    state_path: Path,
    rounds_path: Path,
    horizon_keys_dir: Path,
    round_size: int = 5,
) -> Tuple[Dict[str, Any], Dict[str, Any] | None]:
    """Append an event to the current round buffer.

    When buffer reaches `round_size`, commit the round:
    - compute round_hash = sha256(canonical_round)
    - sign round_hash with Horizon master key
    - append to rounds log

    Returns: (round_state, committed_round_or_none)
    """
    state = _load_json(state_path, {"round_counter": 0, "last_round_hash": "", "current": None})

    cur = state.get("current")
    if not isinstance(cur, dict):
        state["round_counter"] = int(state.get("round_counter") or 0) + 1
        cur = {
            "round_id": int(state["round_counter"]),
            "ts_start": time.time(),
            "events": [],
        }
        state["current"] = cur

    cur.setdefault("events", [])
    cur["events"].append(event)

    committed = None
    if len(cur["events"]) >= int(round_size):
        round_obj = {
            "round_id": cur.get("round_id"),
            "ts_start": cur.get("ts_start"),
            "ts_end": time.time(),
            "prev_round_hash": state.get("last_round_hash") or "",
            "events": cur.get("events") or [],
        }
        round_hash = _sha256_hex(_canon(round_obj))
        sig = _sign_round_hash(round_hash, horizon_keys_dir)
        round_obj.update(sig)

        rounds = _load_json(rounds_path, {"rounds": []})
        rounds.setdefault("rounds", [])
        rounds["rounds"].append(round_obj)
        # keep last 200 rounds (prototype)
        rounds["rounds"] = rounds["rounds"][-200:]
        _save_json(rounds_path, rounds)

        state["last_round_hash"] = round_hash
        state["current"] = None
        committed = round_obj

    _save_json(state_path, state)
    return state, committed


def get_rounds(rounds_path: Path) -> List[Dict[str, Any]]:
    rounds = _load_json(rounds_path, {"rounds": []}).get("rounds", [])
    if not isinstance(rounds, list):
        return []
    return rounds


def get_round_state(state_path: Path) -> Dict[str, Any]:
    return _load_json(state_path, {"round_counter": 0, "last_round_hash": "", "current": None})

# Backward-compatible helper expected by app.py
def add_event_to_round(state_path: Path, rounds_path: Path, horizon_keys_dir: Path, event: dict, round_size: int = 5):
    """Append an event to the rounds buffer.

    Signature matches the call sites in app.py:
    add_event_to_round(Path(ROUNDS_STATE_FILE), Path(ROUNDS_FILE), Path(HORIZON_MASTER_KEYS_DIR), event)
    """
    # Append to tamper-evident local event chain (append-only JSONL).
    # Chain is anchored by Horizon-signed round commitments.
    try:
        data_dir = state_path.parent
        chain_log = data_dir / "event_chain.jsonl"
        chain_state = data_dir / "event_chain_state.json"
        append_event(log_path=chain_log, state_path=chain_state, etype=str(event.get("type") or "EVENT"), payload=event)
    except Exception:
        pass

    st, committed = add_event(
        event=event,
        state_path=state_path,
        rounds_path=rounds_path,
        horizon_keys_dir=horizon_keys_dir,
        round_size=round_size,
    )

    # Anchor the chain with Horizon-signed committed rounds.
    if committed:
        try:
            data_dir = state_path.parent
            chain_log = data_dir / "event_chain.jsonl"
            chain_state = data_dir / "event_chain_state.json"
            append_event(
                log_path=chain_log,
                state_path=chain_state,
                etype="ROUND_COMMITTED",
                payload={
                    "round_id": committed.get("round_id"),
                    "round_hash": committed.get("round_hash"),
                    "prev_round_hash": committed.get("prev_round_hash"),
                    "events_count": len(committed.get("events") or []),
                    "horizon_sig_b64": committed.get("horizon_sig_b64"),
                    "horizon_pub_pem": committed.get("horizon_pub_pem"),
                },
                anchor=True,
            )
        except Exception:
            pass

    return st, committed
