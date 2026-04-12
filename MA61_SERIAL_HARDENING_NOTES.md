# MA61 — SERIAL hardening

- Added `_serial_exchange(...)` in `core/firmware_bridge.py`
- SERIAL transport now fails fast on protocol errors like `bad_crc` / `bad_len`
- Timeout loop now retries only transient read failures until timeout budget expires
- Added negative tests for bad CRC, silent timeout, and bad length framing
