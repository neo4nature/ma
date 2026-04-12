# MA59 — Blueprint Cleanup Notes

## What changed
- extracted remaining system/media/chain/receipts routes from `app.py` into:
  - `routes/system.py`
  - `services/system_service.py`
- registered new blueprint `system_bp`
- removed direct `@app.route(...)` decorators for:
  - `/`
  - `/media`
  - `/media/new`
  - `/media/create`
  - `/api/chain/head`
  - `/api/chain/events`
  - `/api/chain/import`
  - `/api/receipts`
- kept legacy implementation functions in `app.py` to avoid behavior changes
- added regression tests for home/media/chain/receipts routes

## Outcome
- `app.py` is lighter and almost fully decoupled from direct route registration
- behavior remains unchanged while route ownership moves to blueprints

- added a simple `/story` route via system blueprint to keep legacy navigation stable
