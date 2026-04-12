"""MA Peer routing v0 (stdlib only).

What it does:
- peers.json (manual list of base URLs)
- fetch missing chunks over HTTP: GET /api/blob/chunk/<sha>
- peer reputation (success/fail/latency) stored locally in peer_stats.json
- best-effort cache limiting (LRU-ish via mtime), with optional pin protection
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


def _now() -> float:
    return float(time.time())


def load_peers(peers_file: str) -> List[str]:
    """Load peers from JSON. Accepts {'peers':[...]} or bare list."""
    try:
        p = Path(peers_file)
        if not p.exists():
            return []
        data = json.loads(p.read_text(encoding='utf-8'))
        peers = data.get('peers') if isinstance(data, dict) else data
        if not isinstance(peers, list):
            return []
        out: List[str] = []
        for x in peers:
            if not isinstance(x, str):
                continue
            x = x.strip().rstrip('/')
            if x.startswith('http://') or x.startswith('https://'):
                out.append(x)
        return sorted(set(out))
    except Exception:
        return []


def _chunk_path(blob_dir: str, sha256_hex: str) -> str:
    return os.path.join(blob_dir, f"{sha256_hex}.bin")


def load_peer_stats(stats_file: str) -> Dict[str, Dict]:
    """Load peer stats map keyed by base URL."""
    try:
        p = Path(stats_file)
        if not p.exists():
            return {}
        obj = json.loads(p.read_text(encoding='utf-8'))
        if not isinstance(obj, dict):
            return {}
        data = obj.get('peers') if 'peers' in obj else obj
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_peer_stats(stats_file: str, stats: Dict[str, Dict]) -> None:
    p = Path(stats_file)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {"v": 1, "updated_at": _now(), "peers": stats}
    tmp = str(p) + '.tmp'
    Path(tmp).write_text(json.dumps(payload, ensure_ascii=False, separators=(',', ':'), sort_keys=True), encoding='utf-8')
    Path(tmp).replace(p)


def _update_peer_stat(stats: Dict[str, Dict], peer: str, *, ok: bool, latency_ms: Optional[float] = None) -> None:
    rec = stats.get(peer) if isinstance(stats.get(peer), dict) else {}
    rec.setdefault('success', 0)
    rec.setdefault('fail', 0)
    rec.setdefault('avg_latency_ms', None)
    rec.setdefault('last_seen', None)
    rec.setdefault('last_ok', None)

    if ok:
        rec['success'] = int(rec.get('success') or 0) + 1
        rec['last_ok'] = _now()
    else:
        rec['fail'] = int(rec.get('fail') or 0) + 1

    if latency_ms is not None:
        try:
            latency_ms = float(latency_ms)
            prev = rec.get('avg_latency_ms')
            if prev is None:
                rec['avg_latency_ms'] = latency_ms
            else:
                # EMA-ish smoothing
                rec['avg_latency_ms'] = (0.7 * float(prev)) + (0.3 * latency_ms)
        except Exception:
            pass

    rec['last_seen'] = _now()
    stats[peer] = rec


def rank_peers(peers: List[str], stats: Dict[str, Dict]) -> List[str]:
    """Return peers sorted by best estimated reliability/latency."""
    def score(p: str) -> Tuple[float, float, float]:
        r = stats.get(p) if isinstance(stats.get(p), dict) else {}
        s = float(r.get('success') or 0)
        f = float(r.get('fail') or 0)
        # Laplace smoothing for success rate
        rate = (s + 1.0) / (s + f + 2.0)
        lat = r.get('avg_latency_ms')
        lat = float(lat) if isinstance(lat, (int, float)) else 10_000.0
        last_ok = float(r.get('last_ok') or 0.0)
        # sort: higher rate first, lower latency, more recent ok
        return (-rate, lat, -last_ok)

    return sorted(peers, key=score)


def fetch_chunk(peer_base: str, sha256_hex: str, timeout_s: float = 5.0) -> Tuple[Optional[bytes], Optional[float]]:
    url = f"{peer_base}/api/blob/chunk/{sha256_hex}"
    req = urllib.request.Request(url, method='GET')
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status = getattr(resp, 'status', 200)
            if status != 200:
                return None, (time.time() - t0) * 1000.0
            data = resp.read()
            return (data if data else None), (time.time() - t0) * 1000.0
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        return None, (time.time() - t0) * 1000.0
    except Exception:
        return None, (time.time() - t0) * 1000.0


def ensure_chunk_present(
    blob_dir: str,
    sha256_hex: str,
    peers: List[str],
    timeout_s: float = 5.0,
    cache_max_bytes: Optional[int] = None,
    pinned: Optional[Set[str]] = None,
    peer_stats_file: Optional[str] = None,
) -> bool:
    if not sha256_hex or len(sha256_hex) != 64:
        return False
    sha256_hex = sha256_hex.strip().lower()
    if any(c not in "0123456789abcdef" for c in sha256_hex):
        return False
    os.makedirs(blob_dir, exist_ok=True)
    path = _chunk_path(blob_dir, sha256_hex)
    if os.path.exists(path):
        try:
            os.utime(path, None)
        except Exception:
            pass
        return True

    stats = load_peer_stats(peer_stats_file) if peer_stats_file else {}
    ordered = rank_peers(peers, stats)

    for peer in ordered:
        data, lat_ms = fetch_chunk(peer, sha256_hex, timeout_s=timeout_s)
        if data is None:
            _update_peer_stat(stats, peer, ok=False, latency_ms=lat_ms)
            continue

        # Critical safety: verify content-addressed integrity before writing.
        digest = hashlib.sha256(data).hexdigest()
        if digest != sha256_hex:
            _update_peer_stat(stats, peer, ok=False, latency_ms=lat_ms)
            continue

        _update_peer_stat(stats, peer, ok=True, latency_ms=lat_ms)
        tmp = path + '.tmp'
        with open(tmp, 'wb') as f:
            f.write(data)
        os.replace(tmp, path)
        try:
            os.utime(path, None)
        except Exception:
            pass
        if cache_max_bytes is not None:
            enforce_cache_limit(blob_dir, cache_max_bytes, pinned=pinned)
        if peer_stats_file:
            save_peer_stats(peer_stats_file, stats)
        return True
    if peer_stats_file:
        save_peer_stats(peer_stats_file, stats)
    return False


def _dir_size_bytes(blob_dir: str) -> int:
    total = 0
    for root, _, files in os.walk(blob_dir):
        for fn in files:
            if not fn.endswith('.bin'):
                continue
            try:
                total += os.path.getsize(os.path.join(root, fn))
            except OSError:
                pass
    return total


def enforce_cache_limit(blob_dir: str, max_bytes: int, pinned: Optional[Set[str]] = None) -> None:
    """Delete oldest chunks until directory fits max_bytes (best-effort)."""
    if max_bytes <= 0 or not os.path.isdir(blob_dir):
        return
    total = _dir_size_bytes(blob_dir)
    if total <= max_bytes:
        return

    now = time.time()
    candidates = []
    pinned = pinned or set()
    for root, _, files in os.walk(blob_dir):
        for fn in files:
            if not fn.endswith('.bin'):
                continue
            # Skip pinned chunks
            chunk_id = fn[:-4]
            if chunk_id in pinned:
                continue
            p = os.path.join(root, fn)
            try:
                st = os.stat(p)
            except OSError:
                continue
            if now - st.st_mtime < 10:
                continue
            candidates.append((st.st_mtime, p, st.st_size))

    candidates.sort(key=lambda x: x[0])
    for _, p, sz in candidates:
        if total <= max_bytes:
            break
        try:
            os.remove(p)
            total -= int(sz)
        except OSError:
            continue
