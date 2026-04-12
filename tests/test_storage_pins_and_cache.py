import os
import tempfile
import unittest

from core.storage_chunks import chunk_and_store
from core.pin_store import add_pins, load_pins
from core.peer_router import enforce_cache_limit


class TestPinsAndCache(unittest.TestCase):
    def test_pinned_chunks_not_evicted(self):
        with tempfile.TemporaryDirectory() as d:
            blob_dir = os.path.join(d, "blob")
            pins_file = os.path.join(d, "pins.json")

            # Create 3 chunks (~1MB total)
            data = (b"a" * (256 * 1024)) + (b"b" * (256 * 1024)) + (b"c" * (256 * 1024))
            refs = chunk_and_store(fp=_BytesIO(data), blob_dir=blob_dir, chunk_size=256 * 1024)
            self.assertEqual(len(refs), 3)

            # Pin the first two
            add_pins(pins_file, [refs[0].sha256_hex, refs[1].sha256_hex])
            pins = load_pins(pins_file)
            self.assertIn(refs[0].sha256_hex, pins)
            self.assertIn(refs[1].sha256_hex, pins)

            # Force eviction to very small size; only unpinned should be removed
            enforce_cache_limit(blob_dir, max_bytes=10, pinned=pins)

            # Pinned remain
            self.assertTrue(os.path.exists(os.path.join(blob_dir, refs[0].sha256_hex + ".bin")))
            self.assertTrue(os.path.exists(os.path.join(blob_dir, refs[1].sha256_hex + ".bin")))

            # Unpinned may be removed
            # (best-effort: if it survives due to timing guard, touch mtimes and retry)
            third_path = os.path.join(blob_dir, refs[2].sha256_hex + ".bin")
            if os.path.exists(third_path):
                os.utime(third_path, (0, 0))
                enforce_cache_limit(blob_dir, max_bytes=10, pinned=pins)
            self.assertFalse(os.path.exists(third_path))


class _BytesIO:
    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def read(self, n: int) -> bytes:
        if self._pos >= len(self._data):
            return b""
        out = self._data[self._pos : self._pos + n]
        self._pos += len(out)
        return out


if __name__ == "__main__":
    unittest.main()
