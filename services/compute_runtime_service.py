"""Compute runtime helpers extracted from app.py.

These helpers keep runtime behavior unchanged while reducing the size and
responsibility of app.py. The app module still exposes thin compatibility
wrappers so existing tests and monkeypatches remain stable.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import subprocess
import time
import uuid
from pathlib import Path

from PIL import Image
from flask import request

from core.safe_fs import UnsafePath, safe_mkdirs, safe_resolve_file


def worker_tick_authorized(*, configured_token: str) -> bool:
    """Require a shared worker token when configured."""
    token = (configured_token or "").strip()
    if not token:
        return True
    header_token = (request.headers.get("X-Worker-Token") or "").strip()
    auth = (request.headers.get("Authorization") or "").strip()
    bearer_token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    candidate = header_token or bearer_token
    return bool(candidate) and secrets.compare_digest(candidate, token)


def refund_compute_job_escrow_once(
    *,
    base_dir: str,
    job_id: str,
    reason: str,
    escrow_account: str,
    get_compute_job,
    set_compute_job_settlement,
    wallet_transfer_internal,
) -> dict:
    """Best-effort refund helper guarded against duplicate payout/refund."""
    fresh = get_compute_job(base_dir, str(job_id)) or {}
    escrow_amount = float(fresh.get("escrow_amount") or 0.0)
    escrow_status = str(fresh.get("escrow_status") or "NONE").upper()
    owner = str(fresh.get("owner") or "")
    if not owner or escrow_amount <= 0:
        return {"ok": False, "skipped": True, "reason": "no_escrow"}
    if escrow_status in ("REFUNDED", "PAID"):
        return {"ok": True, "skipped": True, "reason": escrow_status.lower()}
    ref = wallet_transfer_internal(
        escrow_account,
        owner,
        escrow_amount,
        f"COMPUTE_REFUND:{job_id}:{reason}",
    )
    if ref.get("ok"):
        set_compute_job_settlement(
            base_dir,
            job_id=str(job_id),
            escrow_status="REFUNDED",
            refund_tx_id=(ref.get("tx") or {}).get("id"),
        )
    return {
        "ok": bool(ref.get("ok")),
        "skipped": False,
        "tx_id": (ref.get("tx") or {}).get("id"),
        "owner": owner,
        "amount": escrow_amount,
    }


def sha256_hex_path(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_b64_json(obj: dict) -> str:
    b = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.b64encode(hashlib.sha256(b).digest()).decode("ascii")


def execute_compute_job_local(job: dict, *, data_dir: str) -> tuple[str | None, str | None]:
    """Execute a job locally (prototype worker)."""
    kind = (job.get("kind") or "").strip() or "render_stub"
    src_rel = job.get("src_relpath") or ""
    src_abs = os.path.join(data_dir, src_rel)
    if not os.path.exists(src_abs):
        return None, None

    safe_mkdirs(Path(data_dir), "compute_results")
    job_id = job.get("id") or str(uuid.uuid4())

    if kind == "thumb_v1":
        out_abs = str(safe_resolve_file(Path(data_dir), os.path.join("compute_results", f"{job_id}_thumb.png")))
        try:
            ext = os.path.splitext(src_abs)[1].lower()
            if ext in (".mp4", ".mov", ".mkv", ".webm", ".avi"):
                cmd = [
                    "ffmpeg",
                    "-y",
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-ss",
                    "00:00:01",
                    "-i",
                    src_abs,
                    "-frames:v",
                    "1",
                    "-vf",
                    "scale='min(256,iw)':-1",
                    out_abs,
                ]
                subprocess.run(cmd, check=True, timeout=25)
            else:
                img = Image.open(src_abs)
                img.thumbnail((256, 256))
                img.save(out_abs, format="PNG")
        except Exception:
            out_abs = str(safe_resolve_file(Path(data_dir), os.path.join("compute_results", f"{job_id}_thumb.json")))
            with open(out_abs, "w", encoding="utf-8") as f:
                json.dump({"kind": "thumb_v1", "status": "failed", "note": "image_open_failed"}, f, ensure_ascii=False)

        rel = os.path.join("compute_results", os.path.basename(out_abs))
        return rel, sha256_hex_path(out_abs)

    out_abs = str(safe_resolve_file(Path(data_dir), os.path.join("compute_results", f"{job_id}_result.json")))
    meta = {
        "job_id": job_id,
        "kind": kind,
        "src_hash_hex": sha256_hex_path(src_abs),
        "note": "prototype_result_stub",
        "ts": time.time(),
    }
    with open(out_abs, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    rel = os.path.join("compute_results", os.path.basename(out_abs))
    return rel, sha256_hex_path(out_abs)
