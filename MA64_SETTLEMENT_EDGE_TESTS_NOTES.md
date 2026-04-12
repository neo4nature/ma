# MA64 — Settlement edge tests and treasury fee hardening

## What changed
- Added stronger edge-case tests for compute settlement.
- Clamped treasury cut behavior is now covered by tests.
- Settlement now avoids reducing owner payout when the treasury fee transfer itself fails.
- Added guard coverage for already-settled jobs (`PAID` / `REFUNDED`) to prevent duplicate side effects.

## Why this matters
Settlement is one of the most sensitive trust boundaries in MA. These tests and the small fee-path fix make payout behavior more predictable under partial failure, without changing the broader runtime flow.
