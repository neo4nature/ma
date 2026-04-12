# Host ↔ Wallet protocol (v0 → v1 plan)

## v0 (current)
App can call wallet functions in-process **or** go through `core/firmware_bridge.py` into `daemon/walletd.py` for TCP / SERIAL PTY transport. This is still a dev boundary, not final hardware isolation.

## v1 (next)
Introduce a strict boundary:
- Web/App becomes a **host**
- Wallet becomes a **device/daemon** (USB / serial / TCP localhost for dev)
- Host never sees raw private keys

### Message envelope (recommended)
Use a signed, length-delimited envelope (JSON for dev, binary for prod):

Fields:
- `type` (string): e.g. `GET_PUBKEY`, `SIGN_TX`, `E2E_DERIVE`, `HORIZON_VOTE`
- `req_id` (string): unique id
- `payload` (object/bytes): request data
- `nonce` (bytes): anti-replay
- `ts` (int): unix timestamp
- `host_sig` (bytes): optional host signature (device can ignore in dev)

Device response:
- `req_id`
- `status` (`OK`/`ERR`)
- `payload`
- `device_sig` (bytes): signature over response hash (device attestation)

### Hard rules
- Private keys **never leave** the device.
- Device verifies anti-replay (nonce window) and rate limits.
- All signing requests are passed through 5-AI + Horizon **inside** the device boundary.

## Migration path
1) Keep Python wallet core as reference implementation.
2) Add `walletd/` (daemon) using the same logic.
3) Swap Flask to call walletd over local socket.
4) Later replace walletd with firmware running on MCU.
