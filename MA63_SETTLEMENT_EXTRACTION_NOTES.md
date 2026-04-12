# MA63 — Settlement Extraction Notes

## What changed
- Extracted internal wallet-transfer helper from `app.py` into `services/settlement_service.py`.
- Extracted compute payout/refund settlement block into a dedicated `settle_compute_job(...)` helper.
- Kept thin compatibility wrappers in `app.py` so runtime behavior and monkeypatching remain stable.
- Added focused regression tests for payout, treasury cut, refund, and blocked internal transfers.

## Why
This reduces business-logic density in `app.py` and makes settlement behavior easier to test in isolation.
