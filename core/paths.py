"""MA path resolution helpers.

Goal (v0.x): unify all on-disk paths behind environment variables so we can:
  - keep runtime artifacts out of the repo
  - move data to encrypted volumes easily
  - avoid "two sources of truth" (data/ vs runtime/)

Conventions:
  - MA_DATA_DIR    : large runtime data (db, chain, blobstore, jobs, caches)
  - MA_SECRETS_DIR : sensitive material (encrypted key vaults, device keys, etc.)

Defaults (safe enough for prototype):
  - MA_DATA_DIR    -> <project_root>/runtime
  - MA_SECRETS_DIR -> <MA_DATA_DIR>/secrets

NOTE: This module is intentionally dependency-light.
"""

from __future__ import annotations

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    # Default to runtime/ (kept out of source control, matches our "runtime is a marker" model).
    d = Path(os.getenv("MA_DATA_DIR") or (PROJECT_ROOT / "runtime"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def secrets_dir() -> Path:
    d = Path(os.getenv("MA_SECRETS_DIR") or (data_dir() / "secrets"))
    d.mkdir(parents=True, exist_ok=True)
    # Best-effort tighten permissions (ignored on some platforms/filesystems)
    try:
        os.chmod(d, 0o700)
    except Exception:
        pass
    return d


def wallet_keys_dir() -> Path:
    d = secrets_dir() / "keys_wallet"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except Exception:
        pass
    return d
