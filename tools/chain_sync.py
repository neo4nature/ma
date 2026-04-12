"""Chain sync tool (prototype).

Usage:
  python tools/chain_sync.py --data-dir runtime

It reads peers from <data-dir>/peers.json and tries to import missing events
from the best peer.

Protocol:
  GET  {peer}/api/chain/head
  GET  {peer}/api/chain/events?from_seq=<local_seq+1>&limit=<...>

Import rules are enforced by core.event_chain.import_events:
  - contiguous seq
  - first prev_hash matches local last_hash
  - hashes verified
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.event_chain import import_events
from core.peer_router import load_peers, load_peer_stats, rank_peers, save_peer_stats, _update_peer_stat


def _get_json(url: str, timeout_s: float = 5.0) -> Tuple[Optional[Dict], float]:
    t0 = __import__("time").time()
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            data = resp.read()
        obj = json.loads(data.decode("utf-8"))
        return obj if isinstance(obj, dict) else None, ( __import__("time").time() - t0) * 1000.0
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        return None, ( __import__("time").time() - t0) * 1000.0
    except Exception:
        return None, ( __import__("time").time() - t0) * 1000.0


def local_head(data_dir: Path) -> Tuple[int, str]:
    state_path = data_dir / "event_chain_state.json"
    if not state_path.exists():
        return 0, ""
    try:
        obj = json.loads(state_path.read_text(encoding="utf-8"))
        return int(obj.get("seq") or 0), str(obj.get("last_hash") or "")
    except Exception:
        return 0, ""


def sync_once(data_dir: Path, limit: int = 5000, timeout_s: float = 5.0) -> Dict:
    peers_file = data_dir / "peers.json"
    stats_file = data_dir / "peer_stats.json"

    peers = load_peers(str(peers_file))
    if not peers:
        return {"ok": False, "reason": "no_peers"}

    stats = load_peer_stats(str(stats_file))
    ordered = rank_peers(peers, stats)

    lseq, _lhash = local_head(data_dir)
    from_seq = lseq + 1

    for peer in ordered:
        head_url = f"{peer}/api/chain/head"
        head, lat1 = _get_json(head_url, timeout_s=timeout_s)
        _update_peer_stat(stats, peer, ok=bool(head and head.get("ok")), latency_ms=lat1)
        if not head or not head.get("ok"):
            continue
        rseq = int((head.get("head") or {}).get("seq") or 0)
        if rseq < from_seq:
            save_peer_stats(str(stats_file), stats)
            return {"ok": True, "imported": 0, "reason": "up_to_date", "peer": peer, "local_seq": lseq, "remote_seq": rseq}

        ev_url = f"{peer}/api/chain/events?from_seq={from_seq}&limit={int(limit)}"
        bundle, lat2 = _get_json(ev_url, timeout_s=timeout_s)
        _update_peer_stat(stats, peer, ok=bool(bundle and bundle.get("ok")), latency_ms=lat2)
        if not bundle or not bundle.get("ok"):
            continue
        events = bundle.get("events")
        if not isinstance(events, list) or not events:
            save_peer_stats(str(stats_file), stats)
            return {"ok": True, "imported": 0, "reason": "no_new_events", "peer": peer}

        res = import_events(log_dir=data_dir, events=events)
        # mark peer ok only if import ok
        _update_peer_stat(stats, peer, ok=bool(res.get("ok")))
        save_peer_stats(str(stats_file), stats)
        res["peer"] = peer
        return res

    save_peer_stats(str(stats_file), stats)
    return {"ok": False, "reason": "no_working_peer"}


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="runtime", help="Runtime data directory (default: runtime)")
    ap.add_argument("--limit", type=int, default=5000)
    ap.add_argument("--timeout", type=float, default=5.0)
    args = ap.parse_args(argv)

    data_dir = Path(args.data_dir).resolve()
    out = sync_once(data_dir, limit=args.limit, timeout_s=args.timeout)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
