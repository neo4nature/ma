from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

from flask import abort, jsonify, request, session

_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# In-memory limiter is acceptable for v0 hardening. It is process-local and
# intentionally simple so it does not add external dependencies.
_RATE_WINDOWS: dict[tuple[str, str], deque[float]] = defaultdict(deque)


def _client_ip() -> str:
    forwarded = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return forwarded or request.remote_addr or "unknown"


def _is_same_origin(value: str | None) -> bool:
    if not value:
        return True
    try:
        parsed = urlparse(value)
        if not parsed.scheme or not parsed.netloc:
            return True
        return parsed.netloc == request.host
    except Exception:
        return False


def _enforce_same_origin() -> None:
    if request.method.upper() not in _STATE_CHANGING_METHODS:
        return
    # Worker token endpoints and machine-to-machine clients may not send browser
    # origin headers, so we skip them here and rely on dedicated auth.
    if request.path == "/api/compute/worker/tick":
        return
    origin = request.headers.get("Origin")
    referer = request.headers.get("Referer")
    if origin and not _is_same_origin(origin):
        abort(403)
    if referer and not _is_same_origin(referer):
        abort(403)


def _limit_key() -> tuple[str, str]:
    return (_client_ip(), request.path)


def _apply_rate_limit() -> tuple[bool, int]:
    method = request.method.upper()
    path = request.path
    limits = {
        "/login": (10, 60),
        "/register": (10, 60),
        "/fid/challenge": (20, 60),
        "/fid/verify": (20, 60),
        "/fid/login_wallet": (20, 60),
        "/feed/create": (30, 60),
        "/feed/attach": (30, 60),
        "/storage/upload": (20, 60),
        "/storage/assemble/create": (30, 60),
        "/api/pool/ping": (180, 60),
        "/api/compute/worker/tick": (180, 60),
        "/api/account/keys/rotate": (20, 60),
        "/api/account/recovery": (30, 60),
    }
    if path not in limits:
        return True, 0
    # Only limit state-changing calls plus FID GET-less auth requests.
    if method not in _STATE_CHANGING_METHODS:
        return True, 0
    max_hits, window_s = limits[path]
    override = os.getenv("MA_RATE_LIMIT_OVERRIDE")
    if override:
        try:
            max_hits = max(1, int(override))
        except Exception:
            pass
    now = time.time()
    bucket = _RATE_WINDOWS[_limit_key()]
    cutoff = now - window_s
    while bucket and bucket[0] < cutoff:
        bucket.popleft()
    if len(bucket) >= max_hits:
        retry_after = max(1, int(window_s - (now - bucket[0])))
        return False, retry_after
    bucket.append(now)
    return True, 0




def reset_rate_limits() -> None:
    _RATE_WINDOWS.clear()

def install_security(app) -> None:
    @app.before_request
    def _ma_security_guards():
        _enforce_same_origin()
        ok, retry_after = _apply_rate_limit()
        if ok:
            return None
        payload = {"ok": False, "error": "rate_limited", "retry_after": retry_after}
        resp = jsonify(payload)
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after)
        return resp

    @app.after_request
    def _ma_security_headers(resp):
        resp.headers.setdefault('X-Frame-Options', 'DENY')
        resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
        resp.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
        resp.headers.setdefault('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; media-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
        return resp
