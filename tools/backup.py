#!/usr/bin/env python3
"""
MA Backup/Restore tool (v0.12)

Creates a consistent snapshot (zip) of:
- runtime/event chain segments (jsonl and related)
- runtime/blobstore (chunks + assemblies)
- runtime/users.json, messages.json, ma.db
- runtime/keys_* directories

Commands:
  python tools/backup.py create [--out data/backups]
  python tools/backup.py verify <snapshot.zip>
  python tools/backup.py restore <snapshot.zip> [--into <base_dir>]

Notes:
- Best-effort "atomic": we build in temp then move.
- For production: pause writers or use fs snapshot.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import List, Tuple

DATA_SUBDIR = os.getenv('MA_DATA_DIR_SUBDIR', 'runtime')

INCLUDE_PATHS = [
    f"{DATA_SUBDIR}/ma.db",
    f"{DATA_SUBDIR}/users.json",
    f"{DATA_SUBDIR}/messages.json",
    f"{DATA_SUBDIR}/posts_seed.json",
    f"{DATA_SUBDIR}/wallet_state.json",
    f"{DATA_SUBDIR}/comm_rate.json",
    f"{DATA_SUBDIR}/event_chain.jsonl",
    f"{DATA_SUBDIR}/event_chain_state.json",
    f"{DATA_SUBDIR}/blobstore",
    f"{DATA_SUBDIR}/keys_wallet",
    f"{DATA_SUBDIR}/keys_comm",
    f"{DATA_SUBDIR}/keys_horizon",
    f"{DATA_SUBDIR}/keys_horizon_master",
    f"{DATA_SUBDIR}/peers.json",
    f"{DATA_SUBDIR}/round_state.json",
    f"{DATA_SUBDIR}/rounds.json",
]


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _collect(base_dir: Path) -> List[Path]:
    out: List[Path] = []
    for rel in INCLUDE_PATHS:
        p = base_dir / rel
        if p.is_dir():
            for sub in p.rglob("*"):
                if sub.is_file():
                    out.append(sub)
        elif p.is_file():
            out.append(p)
    # sort for deterministic manifests
    out = sorted(set(out), key=lambda x: str(x))
    return out

def create_snapshot(base_dir: Path, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    name = f"ma_snapshot_{ts}.zip"
    tmp_dir = Path(tempfile.mkdtemp(prefix="ma_backup_"))
    tmp_zip = tmp_dir / (name + ".tmp")

    files = _collect(base_dir)

    manifest = {
        "version": "0.12",
        "created_at": ts,
        "base_dir": str(base_dir),
        "files": [],
    }

    with zipfile.ZipFile(tmp_zip, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for f in files:
            rel = f.relative_to(base_dir)
            sha = _sha256_file(f)
            manifest["files"].append({"path": str(rel), "sha256": sha, "size": f.stat().st_size})
            z.write(f, arcname=str(rel))
        # write manifest
        z.writestr("SNAPSHOT_MANIFEST.json", json.dumps(manifest, ensure_ascii=False, indent=2))

    final_zip = out_dir / name
    os.replace(tmp_zip, final_zip)
    shutil.rmtree(tmp_dir, ignore_errors=True)
    return final_zip

def verify_snapshot(zip_path: Path) -> Tuple[bool, str]:
    if not zip_path.exists():
        return False, "snapshot_not_found"

    with zipfile.ZipFile(zip_path, "r") as z:
        try:
            manifest = json.loads(z.read("SNAPSHOT_MANIFEST.json").decode("utf-8"))
        except Exception:
            return False, "missing_or_invalid_manifest"

        for item in manifest.get("files", []):
            p = item.get("path")
            expected = item.get("sha256")
            try:
                data = z.read(p)
            except KeyError:
                return False, f"missing_file:{p}"
            got = hashlib.sha256(data).hexdigest()
            if got != expected:
                return False, f"hash_mismatch:{p}"
    return True, "ok"

def restore_snapshot(zip_path: Path, into_dir: Path) -> None:
    ok, msg = verify_snapshot(zip_path)
    if not ok:
        raise RuntimeError(f"snapshot_verify_failed:{msg}")

    into_dir = into_dir.resolve()
    into_dir.mkdir(parents=True, exist_ok=True)

    tmp_dir = Path(tempfile.mkdtemp(prefix="ma_restore_"))
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(tmp_dir)

    # move extracted "data" subtree into place (merge, overwrite files)
    src_data = tmp_dir / DATA_SUBDIR
    if not src_data.exists():
        raise RuntimeError("snapshot_missing_runtime_dir")

    dst_data = into_dir / DATA_SUBDIR
    dst_data.mkdir(parents=True, exist_ok=True)

    for item in src_data.rglob("*"):
        rel = item.relative_to(src_data)
        target = dst_data / rel
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)

    shutil.rmtree(tmp_dir, ignore_errors=True)

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_create = sub.add_parser("create")
    p_create.add_argument("--base", default=".", help="Project base dir (contains runtime/)")
    p_create.add_argument("--out", default="runtime/backups", help="Output directory (relative to base)")

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("zip", help="Snapshot zip path")

    p_restore = sub.add_parser("restore")
    p_restore.add_argument("zip", help="Snapshot zip path")
    p_restore.add_argument("--into", default=".", help="Target base dir")

    args = ap.parse_args()

    if args.cmd == "create":
        base = Path(args.base).resolve()
        out = (base / args.out).resolve()
        zp = create_snapshot(base, out)
        print(str(zp))
        return

    if args.cmd == "verify":
        ok, msg = verify_snapshot(Path(args.zip))
        print("OK" if ok else "FAIL", msg)
        sys.exit(0 if ok else 2)

    if args.cmd == "restore":
        restore_snapshot(Path(args.zip), Path(args.into).resolve())
        print("RESTORED")
        return

if __name__ == "__main__":
    main()
