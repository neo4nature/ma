from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


def _canon(obj: Any) -> bytes:
    """Canonical JSON for stable hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


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


def _load_state(state_path: Path) -> Dict[str, Any]:
    return _load_json(
        state_path,
        {
            "seq": 0,
            "last_hash": "",
            "segments": [],
            "active_log": "event_chain.jsonl",
            "last_anchor": {"seq": 0, "event_hash": ""},
        },
    )


def _save_state(state_path: Path, state: Dict[str, Any]) -> None:
    _save_json(state_path, state)


def compute_event_hash(prev_hash: str, payload_hash: str, ts: float, etype: str, meta: Dict[str, Any] | None = None) -> str:
    """Hash that links events into a tamper-evident chain."""
    meta = meta or {}
    body = {
        "prev": prev_hash or "",
        "payload_hash": payload_hash,
        "ts": float(ts),
        "type": str(etype),
        "meta": meta,
    }
    return _sha256_hex(_canon(body))


def append_event(
    *,
    log_path: Path,
    state_path: Path,
    etype: str,
    payload: Dict[str, Any],
    ts: float | None = None,
    meta: Dict[str, Any] | None = None,
    anchor: bool = False,
) -> Dict[str, Any]:
    """Append a new event to an append-only JSONL event chain.

    This is designed for tamper-evidence, not privacy.
    The chain is anchored by Horizon-signed round commitments (when present).
    """
    ts = float(ts if ts is not None else time.time())
    meta = meta or {}

    state = _load_state(state_path)

    # Hardening: rotate log when it grows too large, to reduce blast radius and
    # speed up verification / tail reads. Rotation is append-only.
    _maybe_rotate_log(log_path=log_path, state_path=state_path, state=state)
    seq = int(state.get("seq") or 0) + 1
    prev_hash = str(state.get("last_hash") or "")

    payload_hash = _sha256_hex(_canon(payload))
    event_hash = compute_event_hash(prev_hash, payload_hash, ts, etype, meta)

    rec = {
        "seq": seq,
        "ts": ts,
        "type": etype,
        "payload": payload,
        "payload_hash": payload_hash,
        "prev_hash": prev_hash,
        "event_hash": event_hash,
        "meta": meta,
        "anchor": bool(anchor),
    }

    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")

    state["seq"] = seq
    state["last_hash"] = event_hash

    if bool(anchor):
        state["last_anchor"] = {"seq": seq, "event_hash": event_hash, "ts": ts, "type": etype}
        _append_checkpoint(log_path.parent / "event_chain_checkpoints.jsonl", rec)

    _save_state(state_path, state)

    return rec


def _append_checkpoint(path: Path, event_rec: Dict[str, Any]) -> None:
    """Append an anchor/checkpoint record for fast proofs and audits."""
    path.parent.mkdir(parents=True, exist_ok=True)
    chk = {
        "seq": int(event_rec.get("seq") or 0),
        "ts": float(event_rec.get("ts") or 0.0),
        "type": str(event_rec.get("type") or ""),
        "event_hash": str(event_rec.get("event_hash") or ""),
        "payload_hash": str(event_rec.get("payload_hash") or ""),
        "payload": event_rec.get("payload") or {},
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(chk, ensure_ascii=False, separators=(",", ":")) + "\n")


def _iter_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    yield obj
            except Exception:
                continue


def _maybe_rotate_log(*, log_path: Path, state_path: Path, state: Dict[str, Any]) -> None:
    """Rotate the active JSONL file when it exceeds size/event limits."""
    # conservative limits for prototype; tweak later.
    max_bytes = 5 * 1024 * 1024  # 5MB
    max_events_per_segment = 10_000

    try:
        if not log_path.exists():
            return
        size = log_path.stat().st_size
        seq = int(state.get("seq") or 0)
        # segment start seq is last segment end + 1
        segments = state.get("segments") or []
        seg_start = 1
        if segments:
            seg_start = int(segments[-1].get("to_seq") or 0) + 1
        seg_len = seq - seg_start + 1

        if size < max_bytes and seg_len < max_events_per_segment:
            return

        # rotate: rename current log to an immutable segment file
        to_seq = seq
        from_seq = max(1, seg_start)
        seg_name = f"event_chain_{from_seq:08d}_{to_seq:08d}.jsonl"
        seg_path = log_path.parent / seg_name
        if seg_path.exists():
            return  # already rotated

        log_path.rename(seg_path)
        segments.append({"file": seg_name, "from_seq": from_seq, "to_seq": to_seq})
        state["segments"] = segments
        state["active_log"] = "event_chain.jsonl"
        _save_state(state_path, state)
    except Exception:
        # Rotation is best-effort; never block appending.
        return


def read_events(
    *,
    log_path: Path,
    state_path: Path | None = None,
    limit: int = 200,
    verify: bool = True,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Read last N events from the event chain (across rotated segments).

    Optionally verify integrity for the returned tail.
    """
    limit = max(1, min(5000, int(limit)))
    state_path = state_path or (log_path.parent / "event_chain_state.json")
    state = _load_state(state_path)

    # Collect tail across immutable segments + active log.
    log_dir = log_path.parent
    segs = state.get("segments") or []
    paths: List[Path] = [log_dir / str(s.get("file")) for s in segs if s.get("file")]
    paths.append(log_path)

    # Read from the end backwards until we have enough lines.
    lines: List[str] = []
    for p in reversed(paths):
        if not p.exists():
            continue
        try:
            with p.open("r", encoding="utf-8") as f:
                chunk_lines = [ln for ln in f if ln.strip()]
            lines = chunk_lines + lines
            if len(lines) >= limit:
                break
        except Exception:
            continue
    tail = lines[-limit:]

    events: List[Dict[str, Any]] = []
    for ln in tail:
        try:
            obj = json.loads(ln)
            if isinstance(obj, dict):
                events.append(obj)
        except Exception:
            continue

    status = {"ok": True, "checked": 0}
    if verify and events:
        ok, checked, bad_seq = verify_events(events)
        status = {"ok": ok, "checked": checked}
        if bad_seq is not None:
            status["bad_seq"] = bad_seq
    return events, status


def verify_full_chain(*, log_dir: Path) -> Dict[str, Any]:
    """Verify the entire event chain across segments + active log."""
    state_path = log_dir / "event_chain_state.json"
    state = _load_state(state_path)
    segs = state.get("segments") or []
    paths: List[Path] = [log_dir / str(s.get("file")) for s in segs if s.get("file")]
    paths.append(log_dir / "event_chain.jsonl")

    expected_prev = ""
    expected_seq = 1
    checked = 0
    for p in paths:
        for e in _iter_jsonl(p):
            seq = int(e.get("seq") or 0)
            if seq != expected_seq:
                return {"ok": False, "checked": checked, "bad_seq": seq, "reason": "seq_gap"}
            if str(e.get("prev_hash") or "") != expected_prev:
                return {"ok": False, "checked": checked, "bad_seq": seq, "reason": "prev_mismatch"}
            # validate event hashes
            ok, _, bad = verify_events([e])
            if not ok:
                return {"ok": False, "checked": checked, "bad_seq": bad or seq, "reason": "hash_mismatch"}
            expected_prev = str(e.get("event_hash") or "")
            expected_seq += 1
            checked += 1

    # Compare with stored state
    return {
        "ok": True,
        "checked": checked,
        "state_seq": int(state.get("seq") or 0),
        "state_last_hash": str(state.get("last_hash") or ""),
        "computed_last_hash": expected_prev,
    }


def export_events(*, log_dir: Path, from_seq: int, limit: int = 2000) -> Dict[str, Any]:
    """Export raw event records from_seq.. (inclusive), across segments + active log.

    This is intended for peer sync and debugging.
    """
    from_seq = max(1, int(from_seq))
    limit = max(1, min(50_000, int(limit)))

    state = _load_state(log_dir / "event_chain_state.json")
    segs = state.get("segments") or []
    paths: List[Path] = [log_dir / str(s.get("file")) for s in segs if s.get("file")]
    paths.append(log_dir / "event_chain.jsonl")

    out: List[Dict[str, Any]] = []
    for p in paths:
        for e in _iter_jsonl(p):
            try:
                seq = int(e.get("seq") or 0)
            except Exception:
                continue
            if seq < from_seq:
                continue
            out.append(e)
            if len(out) >= limit:
                break
        if len(out) >= limit:
            break

    return {
        "ok": True,
        "from_seq": from_seq,
        "count": len(out),
        "events": out,
        "head": {
            "state_seq": int(state.get("seq") or 0),
            "state_last_hash": str(state.get("last_hash") or ""),
        },
    }


def import_events(*, log_dir: Path, events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Import raw event records into the local chain.

    Safety rules (prototype):
    - Events must be a contiguous sequence by seq.
    - First imported event must link to local state_last_hash.
    - Hashes for each event are verified before writing.
    """
    if not isinstance(events, list) or not events:
        return {"ok": False, "reason": "no_events"}

    state_path = log_dir / "event_chain_state.json"
    log_path = log_dir / "event_chain.jsonl"
    state = _load_state(state_path)
    local_seq = int(state.get("seq") or 0)
    local_last = str(state.get("last_hash") or "")

    # Validate sequence continuity
    seqs = []
    for e in events:
        try:
            seqs.append(int(e.get("seq") or 0))
        except Exception:
            return {"ok": False, "reason": "bad_seq"}
    if any(s <= 0 for s in seqs):
        return {"ok": False, "reason": "bad_seq"}
    if seqs[0] != local_seq + 1:
        return {"ok": False, "reason": "not_next", "local_seq": local_seq, "first_seq": seqs[0]}
    for i in range(1, len(seqs)):
        if seqs[i] != seqs[i - 1] + 1:
            return {"ok": False, "reason": "seq_gap", "bad_seq": seqs[i]}

    first_prev = str(events[0].get("prev_hash") or "")
    if first_prev != local_last:
        return {"ok": False, "reason": "prev_mismatch", "expected_prev": local_last, "got_prev": first_prev}

    ok, checked, bad_seq = verify_events(events)
    if not ok:
        return {"ok": False, "reason": "hash_mismatch", "checked": checked, "bad_seq": bad_seq}

    # Append as JSONL records (preserve remote content).
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n")

    state["seq"] = int(events[-1].get("seq") or local_seq)
    state["last_hash"] = str(events[-1].get("event_hash") or local_last)
    _save_state(state_path, state)
    return {"ok": True, "imported": len(events), "new_seq": int(state["seq"]), "new_last_hash": str(state["last_hash"])}


def build_proof(*, log_dir: Path, seq: int) -> Dict[str, Any]:
    """Return a compact proof bundle for a given event sequence number.

    Proof = events from the latest checkpoint/anchor (<= seq) up to the requested seq.
    This allows a verifier to recompute the chain links locally.
    """
    seq = int(seq)
    if seq <= 0:
        return {"ok": False, "reason": "bad_seq"}

    # find nearest checkpoint
    chk_path = log_dir / "event_chain_checkpoints.jsonl"
    anchor_seq = 1
    anchor = None
    for chk in _iter_jsonl(chk_path):
        s = int(chk.get("seq") or 0)
        if s <= seq and s >= anchor_seq:
            anchor_seq = s
            anchor = chk

    events: List[Dict[str, Any]] = []
    # stream all logs, keep only [anchor_seq .. seq]
    state = _load_state(log_dir / "event_chain_state.json")
    segs = state.get("segments") or []
    paths: List[Path] = [log_dir / str(s.get("file")) for s in segs if s.get("file")]
    paths.append(log_dir / "event_chain.jsonl")

    for p in paths:
        for e in _iter_jsonl(p):
            s = int(e.get("seq") or 0)
            if s < anchor_seq:
                continue
            if s > seq:
                break
            events.append(e)

    if not events or int(events[-1].get("seq") or 0) != seq:
        return {"ok": False, "reason": "not_found"}

    ok, checked, bad_seq = verify_events(events)
    return {
        "ok": ok,
        "checked": checked,
        "bad_seq": bad_seq,
        "anchor": anchor,
        "from_seq": anchor_seq,
        "to_seq": seq,
        "events": events,
        "head": {
            "state_seq": int(state.get("seq") or 0),
            "state_last_hash": str(state.get("last_hash") or ""),
        },
    }


def verify_events(events: List[Dict[str, Any]]) -> Tuple[bool, int, int | None]:
    """Verify hashes for a sequence of events (as loaded from the log).

    NOTE: If you verify a *tail* (not full log), the first event's prev_hash
    cannot be validated against an earlier entry. We still validate internal
    consistency for the provided sequence.
    """
    if not events:
        return True, 0, None

    checked = 0
    prev = None
    for i, e in enumerate(events):
        try:
            prev_hash = str(e.get("prev_hash") or "")
            payload = e.get("payload") or {}
            if not isinstance(payload, dict):
                payload = {"_": payload}
            payload_hash = _sha256_hex(_canon(payload))
            ts = float(e.get("ts") or 0.0)
            etype = str(e.get("type") or "")
            meta = e.get("meta") or {}
            if not isinstance(meta, dict):
                meta = {"_": meta}
            expected = compute_event_hash(prev_hash, payload_hash, ts, etype, meta)
            if str(e.get("payload_hash") or "") != payload_hash:
                return False, checked, int(e.get("seq") or -1)
            if str(e.get("event_hash") or "") != expected:
                return False, checked, int(e.get("seq") or -1)

            # Internal linking check (for provided sequence)
            if prev is not None and prev_hash != prev:
                return False, checked, int(e.get("seq") or -1)
            prev = str(e.get("event_hash") or "")
            checked += 1
        except Exception:
            return False, checked, int(e.get("seq") or -1)

    return True, checked, None


def verify_proof_bundle(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Verify a compact proof bundle produced by `build_proof`.

    The verifier recomputes hashes and validates internal linking for the
    provided window. This does *not* require access to the full server log.

    Returns a dict with `ok` plus details.
    """
    if not isinstance(bundle, dict):
        return {"ok": False, "reason": "bad_bundle"}

    events = bundle.get("events")
    if not isinstance(events, list) or not events:
        return {"ok": False, "reason": "no_events"}

    try:
        from_seq = int(bundle.get("from_seq") or int(events[0].get("seq") or 0))
        to_seq = int(bundle.get("to_seq") or int(events[-1].get("seq") or 0))
    except Exception:
        return {"ok": False, "reason": "bad_seq"}

    # Basic sequence checks
    first_seq = int(events[0].get("seq") or 0)
    last_seq = int(events[-1].get("seq") or 0)
    if first_seq != from_seq or last_seq != to_seq:
        return {"ok": False, "reason": "seq_range_mismatch", "from_seq": from_seq, "to_seq": to_seq, "first_seq": first_seq, "last_seq": last_seq}

    # Ensure events are strictly increasing by seq.
    prev_s = None
    for e in events:
        s = int(e.get("seq") or 0)
        if prev_s is not None and s != prev_s + 1:
            return {"ok": False, "reason": "seq_gap", "bad_seq": s}
        prev_s = s

    ok, checked, bad_seq = verify_events(events)
    if not ok:
        return {"ok": False, "reason": "hash_mismatch", "checked": checked, "bad_seq": bad_seq}

    # If bundle includes an anchor/checkpoint, ensure it matches the first event.
    anchor = bundle.get("anchor")
    if isinstance(anchor, dict) and anchor:
        aseq = int(anchor.get("seq") or 0)
        if aseq and aseq != first_seq:
            return {"ok": False, "reason": "anchor_seq_mismatch", "anchor_seq": aseq, "first_seq": first_seq}
        aeh = str(anchor.get("event_hash") or "")
        feh = str(events[0].get("event_hash") or "")
        if aeh and feh and aeh != feh:
            return {"ok": False, "reason": "anchor_hash_mismatch", "anchor_event_hash": aeh, "first_event_hash": feh}

    return {"ok": True, "checked": checked, "from_seq": from_seq, "to_seq": to_seq}
