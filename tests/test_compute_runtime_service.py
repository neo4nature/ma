from pathlib import Path

from services.compute_runtime_service import sha256_b64_json, sha256_hex_path


def test_sha256_b64_json_stable_ordering():
    a = {"b": 2, "a": 1}
    b = {"a": 1, "b": 2}
    assert sha256_b64_json(a) == sha256_b64_json(b)


def test_sha256_hex_path_matches_file_content(tmp_path: Path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"abc123")
    got = sha256_hex_path(str(p))
    assert isinstance(got, str)
    assert len(got) == 64
    assert got == "6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090"
