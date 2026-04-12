# Hardware boundary plan

Goal: evolve from a software wallet to a hardware wallet without rewriting business logic.

## Layers
1. **UI/Host** (Flask / Web)
2. **Wallet boundary** (wallet daemon or USB device)
3. **Secure storage** (SE optional)

## Minimal device responsibilities
- Key generation + storage
- Signing (tx + horizon packets + E2E)
- 5-AI evaluation + Horizon gate
- Anti-replay + rate limiting
- Optional panic wipe

## Dev-friendly bridge (first)
- Run `walletd` as a local process (Unix socket)
- Later swap transport to USB/serial

This keeps the UX evolving while security hardens incrementally.


## Status in MA57
- migration path is active via `core/firmware_bridge.py`
- walletd transport supports TCP and SERIAL PTY for development
- regression tests cover INPROC signing, TCP walletd signing, and frame CRC rejection
