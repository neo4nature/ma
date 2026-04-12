# MA48 patch notes

Included in this package:
- Fixed duplicate/unsafe compute refund flow
- Added refund-once helper guarded by escrow status
- Added immediate refund for queued job cancel endpoint
- Added worker tick shared-token guard via `MA_WORKER_TICK_TOKEN`
- Added regression tests for:
  - worker tick auth
  - queued cancel refund
  - cancel-during-exec refund
- Existing tests still pass

Environment:
- Optional worker auth header:
  - `X-Worker-Token: <token>`
  - or `Authorization: Bearer <token>`
- Configure with `MA_WORKER_TICK_TOKEN`
