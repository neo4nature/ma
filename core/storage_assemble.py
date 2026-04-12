import json
import os
import hashlib
from dataclasses import dataclass
from typing import Dict, Generator, List, Optional, Tuple

from .storage_chunks import open_chunk


@dataclass
class Assembly:
    assembly_id: str
    filename: str
    mime: str
    chunks: List[str]
    total_bytes: int
    created_at: float


def parse_chunk_list(text: str) -> List[str]:
    """Parse a newline-separated list of chunk SHA256 hex ids."""
    if not text:
        return []
    items = [c.strip() for c in text.replace("\r", "").split("\n") if c.strip()]
    # Basic validation
    out: List[str] = []
    for c in items:
        if len(c) != 64:
            raise ValueError("bad_chunk_id")
        int(c, 16)  # raises ValueError
        out.append(c.lower())
    return out


def compute_assembly_id(chunks: List[str]) -> str:
    """Deterministic id for a chunk list."""
    h = hashlib.sha256(("\n".join(chunks)).encode("utf-8")).hexdigest()
    return h


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def assembly_manifest_path(base_dir: str, assembly_id: str) -> str:
    return os.path.join(base_dir, f"{assembly_id}.json")


def load_assembly(base_dir: str, assembly_id: str) -> Assembly:
    path = assembly_manifest_path(base_dir, assembly_id)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return Assembly(
        assembly_id=data["assembly_id"],
        filename=data.get("filename", "") or "",
        mime=data.get("mime", "application/octet-stream") or "application/octet-stream",
        chunks=list(data.get("chunks", [])),
        total_bytes=int(data.get("total_bytes", 0) or 0),
        created_at=float(data.get("created_at", 0) or 0),
    )


def save_assembly(
    base_dir: str,
    assembly_id: str,
    filename: str,
    mime: str,
    chunks: List[str],
    created_at: float,
    total_bytes: int,
) -> str:
    _ensure_dir(base_dir)
    path = assembly_manifest_path(base_dir, assembly_id)
    data: Dict = {
        "assembly_id": assembly_id,
        "filename": filename,
        "mime": mime,
        "chunks": chunks,
        "total_bytes": total_bytes,
        "created_at": created_at,
        "v": 1,
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    os.replace(tmp, path)
    return path


def estimate_total_bytes(blob_dir: str, chunks: List[str], ensure_chunk=None) -> int:
    total = 0
    for c in chunks:
        if ensure_chunk is not None:
            ensure_chunk(c)
        p = open_chunk(blob_dir, c)
        total += os.path.getsize(p)
    return total


def _locate_start(chunks: List[str], sizes: List[int], start: int) -> Tuple[int, int]:
    """Return (chunk_index, offset_in_chunk) for byte position start."""
    if start <= 0:
        return (0, 0)
    pos = 0
    for i, sz in enumerate(sizes):
        if pos + sz > start:
            return (i, start - pos)
        pos += sz
    return (len(chunks), 0)


def iter_assembled_bytes(
    blob_dir: str,
    chunks: List[str],
    range_start: int = 0,
    range_end: Optional[int] = None,
    read_block: int = 1024 * 256,
    ensure_chunk=None,
) -> Generator[bytes, None, None]:
    """Yield assembled bytes for the given chunk list.

    Supports optional range [range_start, range_end] inclusive.
    """
    # Pre-compute sizes to support ranges.
    sizes: List[int] = []
    for c in chunks:
        if ensure_chunk is not None:
            ensure_chunk(c)
        p = open_chunk(blob_dir, c)
        sizes.append(os.path.getsize(p))

    if range_end is not None and range_end < range_start:
        return

    idx, offset = _locate_start(chunks, sizes, range_start)
    if idx >= len(chunks):
        return

    # Remaining bytes to send (if range_end specified)
    remaining = None
    if range_end is not None:
        remaining = (range_end - range_start) + 1

    for i in range(idx, len(chunks)):
        chunk_id = chunks[i]
        if ensure_chunk is not None:
            ensure_chunk(chunk_id)
        path = open_chunk(blob_dir, chunk_id)
        with open(path, "rb") as f:
            if offset:
                f.seek(offset)
            offset = 0
            while True:
                if remaining is not None and remaining <= 0:
                    return
                to_read = read_block
                if remaining is not None:
                    to_read = min(to_read, remaining)
                data = f.read(to_read)
                if not data:
                    break
                if remaining is not None:
                    remaining -= len(data)
                yield data
