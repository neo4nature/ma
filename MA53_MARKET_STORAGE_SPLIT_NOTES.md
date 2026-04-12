# MA53 — Market + Storage route split

What changed:
- added `routes/market_storage.py`
- added `services/market_storage_service.py`
- moved route registration for market + storage under a blueprint
- preserved legacy runtime logic in `app.py`
- updated endpoint references after earlier blueprint splits:
  - market
  - market_create
  - storage_index
  - storage_assemble_index
  - storage_assemble_view
  - compute_create
  - logout
- verified market create and storage upload through tests

Result:
- route split continues without behavior change
- templates now consistently reference blueprint endpoints
- test suite passes
