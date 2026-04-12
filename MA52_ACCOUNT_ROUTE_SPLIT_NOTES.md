# MA52 — Account / Recovery / Key Rotation Route Split

This package continues the progressive decomposition of `app.py` without changing runtime behavior.

## Added
- `routes/account.py`
- `services/account_service.py`

## Moved to blueprint registration
- `/account`
- `/account/preferences`
- `/account/security`
- `/api/account/recovery`
- `/api/account/keys/rotate`

## Notes
- Legacy implementations still live in `app.py`; the new service layer is intentionally thin.
- Updated endpoint references to use `account_routes.*`.
- Moved `@app.after_request` registration before `app.run(...)` so security headers are always attached when running as a script.
