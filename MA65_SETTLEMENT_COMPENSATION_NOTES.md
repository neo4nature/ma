# MA65 — Settlement compensation hardening

What changed:
- Added best-effort compensation transfer from treasury back to escrow when payout fails after a successful treasury fee transfer.
- Added settlement tests for fee-revert success and fee-revert failure reporting.

Why:
- Previously, if the treasury fee transfer succeeded but payout failed, escrow could be partially drained while the job remained unpaid.
- The new behavior preserves clearer economic integrity in partial-failure scenarios.
