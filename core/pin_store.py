"""Pin store for blob chunks.

Pinned chunks are protected from cache eviction.

Storage format (JSON):
{
  "v": 1,
  "pinned": ["<sha256hex>", ...],
  "updated_at": 1234567890.0
}

This module is intentionally simple and stdlib-only.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Iterable, Set


def _valid_sha256_hex(s: str) -> bool:
    if not isinstance(s, str):
        return False
    s = s.strip().lower()
    if len(s) != 64:
        return False
    try:
        int(s, 16)
    except Exception:
        return False
    return True


def load_pins(pins_path: str) -> Set[str]:
    """Load pins from JSON file. Returns a set of sha256 hex ids."""
    try:
        p = Path(pins_path)
        if not p.exists():
            return set()
        obj = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(obj, dict):
            return set()
        items = obj.get("pinned")
        if not isinstance(items, list):
            return set()
        return {x.strip().lower() for x in items if isinstance(x, str) and _valid_sha256_hex(x)}
    except Exception:
        return set()


def save_pins(pins_path: str, pins: Iterable[str]) -> None:
    p = Path(pins_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "v": 1,
        "updated_at": float(time.time()),
        "pinned": sorted({x.strip().lower() for x in pins if isinstance(x, str) and _valid_sha256_hex(x)}),
    }
    tmp = str(p) + ".tmp"
    Path(tmp).write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    Path(tmp).replace(p)


def add_pins(pins_path: str, chunk_ids: Iterable[str]) -> Set[str]:
    pins = load_pins(pins_path)
    for cid in chunk_ids:
        if isinstance(cid, str) and _valid_sha256_hex(cid):
            pins.add(cid.strip().lower())
    save_pins(pins_path, pins)
    return pins


def remove_pins(pins_path: str, chunk_ids: Iterable[str]) -> Set[str]:
    pins = load_pins(pins_path)
    for cid in chunk_ids:
        if isinstance(cid, str):
            pins.discard(cid.strip().lower())
    save_pins(pins_path, pins)
    return pins


def is_pinned(pins: Set[str], chunk_id: str) -> bool:
    if not isinstance(chunk_id, str):
        return False
    return chunk_id.strip().lower() in pins
