"""Filesystem safety helpers.

We harden a few I/O edges that are common foot-guns in webapps:
  - path traversal attempts
  - symlink escape attempts (attacker plants a symlink inside MA_DATA_DIR)

IMPORTANT:
  This is *not* a complete sandbox. It's a pragmatic guardrail.
  The long-term boundary remains: secrets are never handled by the web UI
  process; only a signer (walletd / hardware) touches private keys.
"""

from __future__ import annotations

import os
from pathlib import Path


class UnsafePath(Exception):
    pass


def _is_under(base: Path, target: Path) -> bool:
    base_r = base.resolve()
    try:
        target_r = target.resolve()
    except FileNotFoundError:
        # If target doesn't exist yet, resolve the parent
        target_r = target.parent.resolve() / target.name
    try:
        target_r.relative_to(base_r)
        return True
    except Exception:
        return False


def ensure_no_symlink_components(base: Path, rel: Path) -> Path:
    """Ensure that within base/rel, no existing component is a symlink.

    Returns the concrete path (base/rel).
    """
    if rel.is_absolute():
        raise UnsafePath("absolute_path_not_allowed")

    base_r = base.resolve()
    cur = base_r
    for part in rel.parts:
        if part in ("", "."):
            continue
        if part == "..":
            raise UnsafePath("path_traversal")
        cur = cur / part
        if cur.exists() and cur.is_symlink():
            raise UnsafePath("symlink_component")
    return base_r / rel


def safe_resolve_file(base: Path, rel: str) -> Path:
    """Resolve a relative file path under base, reject traversal & symlink escapes."""
    rel_p = Path(rel)
    p = ensure_no_symlink_components(base, rel_p)
    # Resolve final path and verify it's under base
    if not _is_under(base, p):
        raise UnsafePath("escaped_base")
    # Reject if final file is a symlink
    if p.exists() and p.is_symlink():
        raise UnsafePath("symlink_file")
    return p


def safe_mkdirs(base: Path, rel: str) -> Path:
    """Create a directory under base while rejecting symlink components."""
    rel_p = Path(rel)
    target = ensure_no_symlink_components(base, rel_p)
    if not _is_under(base, target):
        raise UnsafePath("escaped_base")
    # Create each directory segment safely
    cur = base.resolve()
    for part in rel_p.parts:
        if part in ("", "."):
            continue
        cur = cur / part
        if cur.exists():
            if cur.is_symlink():
                raise UnsafePath("symlink_component")
            if not cur.is_dir():
                raise UnsafePath("not_a_directory")
        else:
            cur.mkdir(parents=True, exist_ok=True)
    return target


def tighten_dir_perms(path: Path, mode: int = 0o700) -> None:
    try:
        os.chmod(path, mode)
    except Exception:
        pass
