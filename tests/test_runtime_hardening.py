import pytest

from daemon.walletd import _prune_seen_map, _validate_and_update_replay_guard


def _base_req(**overrides):
    req = {
        "type": "SIGN",
        "v": 2,
        "sender": "neo",
        "counter": 1,
        "nonce_b64": "bm9uY2Ux",
    }
    req.update(overrides)
    return req


def test_replay_guard_requires_positive_counter_and_nonce():
    with pytest.raises(ValueError, match="counter_required"):
        _validate_and_update_replay_guard(_base_req(counter=0), {"last_counter": {}, "seen": {}})

    with pytest.raises(ValueError, match="nonce_required"):
        _validate_and_update_replay_guard(_base_req(nonce_b64=""), {"last_counter": {}, "seen": {}})


def test_replay_guard_rejects_counter_reuse_and_duplicate_nonce_tuple():
    replay = {"last_counter": {}, "seen": {}}
    replay = _validate_and_update_replay_guard(_base_req(counter=1, nonce_b64="bm9uY2Ux"), replay)
    assert replay["last_counter"]["neo"] == 1

    with pytest.raises(ValueError, match="replay_counter"):
        _validate_and_update_replay_guard(_base_req(counter=1, nonce_b64="bm9uY2Uy"), replay)

    replay["last_counter"]["neo"] = 0
    with pytest.raises(ValueError, match="replay_nonce"):
        _validate_and_update_replay_guard(_base_req(counter=1, nonce_b64="bm9uY2Ux"), replay)


def test_prune_seen_map_respects_ttl_and_caps_size():
    seen = {
        "old": 1.0,
        "new1": 10_000_000_000.0,
        "new2": 10_000_000_001.0,
    }
    pruned = _prune_seen_map(seen, ttl_seconds=60)
    assert "old" not in pruned

    crowded = {f"k{i}": float(i) for i in range(6000)}
    trimmed = _prune_seen_map(crowded, ttl_seconds=10_000_000_000, max_items=5000, drop_to=4000)
    assert len(trimmed) == 4000
