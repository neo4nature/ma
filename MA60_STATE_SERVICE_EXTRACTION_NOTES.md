# MA60 — State Service Extraction Notes

This snapshot continues the conservative post-MA59 cleanup by moving legacy
state/persistence helpers out of `app.py` into `services/state_service.py`
without changing runtime behavior.

## What moved
- JSON helpers (`load_json`, `save_json`)
- legacy JSON stores for users/messages/comm rate
- user bootstrap helpers (`ensure_user_records`, `ensure_wallet_secret`)
- posts/media persistence helpers
- feed/media decoration helpers used by UI rendering

## Why
- reduce `app.py` size and cognitive load
- separate persistence/state concerns from route orchestration
- prepare future extraction of remaining business logic into services

## Behavior contract
- file formats unchanged
- route behavior unchanged
- legacy wrappers remain in `app.py` so existing imports/tests keep working

## Validation
- full test suite passes after extraction
