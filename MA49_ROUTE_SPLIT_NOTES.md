# MA49 Route Split Notes

This build starts Sprint 2 with a low-risk extraction of compute routes.

## What changed
- Moved compute HTTP route registration out of `app.py` into `routes/compute.py`
- Added `services/compute_service.py` as a thin service layer wrapper
- Kept legacy compute logic in `app.py` to avoid behavior drift during the first split
- Registered the compute blueprint from `app.py`

## Why this shape
This is an intentionally conservative first cut:
- route registration is now modular,
- tests can target a dedicated route module,
- behavior remains unchanged,
- deeper business-logic extraction can continue safely in the next step.

## Next split candidates
- auth / FID routes
- feed routes
- market routes
- i18n extraction from `app.py`
