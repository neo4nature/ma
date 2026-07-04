# Comm (E2E messenger) resurrection — 2026-07-04

## What happened
The `/comm` messenger (X25519 + HKDF-SHA256 + AES-GCM, born 2025-12-30) lived in
app.py until **ma47**. **ma48_patched** (2026-04-11) shipped an app.py truncated by
853 lines / 26 routes — `/comm*`, `/wallet`, `/users`, `/story`, a dozen `/api/*` —
and the blueprint split (ma49+) was built on the truncated base, so `routes/comm.py`
never existed. The dead cargo (comm.html, core/comm_crypto.py, core/horizon_messages.py,
db messages table, keys_comm dir, post-login redirects to `/comm`) rode along intact.

Full excavation report: Lira ecosystem `shared_library/ma_origin/E2E_MESSENGER_EXCAVATION_2026-07-04.md`.

## What was done
- **app.py**: 4 legacy views restored from ma47 (donor lines 2950-3334): `comm()`,
  `comm_send_money()`, `comm_api_send()`, `comm_api_thread(key)`. Only change:
  `url_for("comm", ...)` → `url_for("comm_routes.comm_route", ...)`.
- **services/comm_service.py**: thin wrappers (feed_service pattern).
- **routes/comm.py**: `comm_bp` (`comm_routes`) with `/comm`, `/comm/send`,
  `/comm/send_money`, `/comm/thread/<path:key>`; registered in app.py.
- **templates/comm.html**: `url_for('comm_send_money')` → blueprint endpoint
  (rest of the template was already migrated to blueprint endpoints).
- **tests/test_comm_routes_split.py**: 5 tests — routes registered, login required,
  full E2E send→store-encrypted→decrypt roundtrip, guard errors, and
  **route inventory guard** (critical-route set + total floor) so a silent file
  truncation can never again pass unnoticed.

## Result
48/48 tests pass (43 existing + 5 new). Post-login redirect to `/comm` works again.
