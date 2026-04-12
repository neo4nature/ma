import os
import hashlib
from dataclasses import dataclass
from typing import BinaryIO, List, Optional


@dataclass
class ChunkRef:
    """A reference to a stored chunk in the local blobstore."""

    sha256_hex: str
    size: int


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def chunk_and_store(
    fp: BinaryIO,
    blob_dir: str,
    chunk_size: int = 1024 * 1024,
    max_bytes: Optional[int] = None,
) -> List[ChunkRef]:
    """Read a file-like stream, split into fixed chunks, store each chunk by SHA-256.

    - Content-addressed: filename is sha256 hex.
    - Deduplicated: if a chunk already exists, we don't rewrite it.
    - Returns ordered list of ChunkRef.
    """
    if chunk_size < 1024:
        raise ValueError("chunk_size_too_small")

    _ensure_dir(blob_dir)
    out: List[ChunkRef] = []
    total = 0

    while True:
        if max_bytes is not None and total >= max_bytes:
            break
        to_read = chunk_size
        if max_bytes is not None:
            to_read = min(to_read, max_bytes - total)

        data = fp.read(to_read)
        if not data:
            break

        total += len(data)
        h = hashlib.sha256(data).hexdigest()
        path = os.path.join(blob_dir, f"{h}.bin")
        if not os.path.exists(path):
            # atomic-ish write
            tmp = path + ".tmp"
            with open(tmp, "wb") as wf:
                wf.write(data)
            os.replace(tmp, path)

        out.append(ChunkRef(sha256_hex=h, size=len(data)))

    return out


def open_chunk(blob_dir: str, sha256_hex: str) -> str:
    """Return absolute path to a chunk, raises FileNotFoundError if missing."""
    if not sha256_hex or len(sha256_hex) != 64:
        raise FileNotFoundError("bad_chunk_id")
    # Validate hex to avoid path tricks and accidental corruption.
    s = sha256_hex.lower()
    if any(c not in "0123456789abcdef" for c in s):
        raise FileNotFoundError("bad_chunk_id")
    path = os.path.join(blob_dir, f"{s}.bin")
    if not os.path.exists(path):
        raise FileNotFoundError("chunk_not_found")
    return path
