# MA62 — Compute Runtime Extraction

This snapshot extracts compute runtime helpers from `app.py` into `services/compute_runtime_service.py` while preserving legacy wrapper names in `app.py` for compatibility and monkeypatch-friendly tests.

Moved helpers:
- worker tick auth
- escrow refund helper
- sha256 helpers for compute proofs
- local compute execution helper

Result: smaller `app.py`, unchanged route behavior, stronger separation between orchestration and compute runtime internals.
