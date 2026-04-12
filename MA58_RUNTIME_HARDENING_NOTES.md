# MA58 — Runtime / Replay Hardening Notes

## Added
- timezone-aware UTC in `wallet/user_keys.py`
- replay-guard helper extraction in `daemon/walletd.py`
- stricter v2 signing validation:
  - sender required
  - counter > 0 required
  - nonce_b64 required
- replay seen-map TTL pruning via `MA_REPLAY_TTL_SECONDS`
- serial timeout loops now use `time.monotonic()` in `core/firmware_bridge.py`

## Why
This tightens signer/runtime boundary behavior and removes a datetime deprecation warning without changing application-facing flows.
