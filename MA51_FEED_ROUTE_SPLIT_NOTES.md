# MA51 — Feed route split notes

This package continues the progressive decomposition of `app.py` without changing
runtime behavior.

## Included in this step
- Added `routes/feed.py`
- Added `services/feed_service.py`
- Registered `feed_bp` blueprint in `app.py`
- Moved route registration for:
  - `/timeline`
  - `/feed`
  - `/feed/attach`
  - `/feed/create`
- Kept underlying feed logic in legacy helpers inside `app.py`
- Updated internal `url_for(...)` references to blueprint endpoints for feed/auth
- Replaced a few broken template endpoint references with current route names or direct paths
- Added tests covering:
  - `/feed`
  - `/timeline` route presence / login gate
  - `/feed/create` persistence and signature verification

## Test status
- `9 passed`

## Intent
This is still a conservative refactor:
- move routing first
- preserve behavior
- reduce monolith gradually
- avoid mixing route extraction with deep business-logic rewrites
