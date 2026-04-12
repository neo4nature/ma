# MA56 — Bridge / walletd tests

This build focuses on signer boundary confidence rather than feature growth.

## Added
- regression tests for `sign_hash_via_firmware()` in `INPROC` mode
- TCP walletd integration test:
  - `DEVICE_HELLO`
  - `SIGN` through socket transport
- framing tests for PTY/TCP helpers:
  - successful roundtrip
  - CRC rejection (`bad_crc`)

## Why this matters
MA is only as trustworthy as the boundary between host/runtime and signer.
This package increases confidence that:
- transport switching still works
- wallet daemon identifies itself correctly
- framing corruption is rejected

## Test status
Expected total after this package: previous suite + bridge tests.
