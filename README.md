# MA — Decentralized P2P Platform

> Local-first. Zero fees. Built for people without banks.

## What is MA?

MA is a peer-to-peer platform where anyone can trade, store, and compute — without banks, without cloud, without cost. Built from a village in Wales on a £200 laptop with a zero budget.

**MA stands for freedom:** if you have a device, you have a marketplace.

## Why?

- 13% eBay fees are not freedom
- Cloud dependency is not resilience  
- English-only platforms are not inclusive
- If it doesn't work offline, it doesn't work for everyone

## Features

- **P2P Marketplace** — list products, trade locally, zero commission
- **Wallet & Settlement** — escrow, treasury, partial-failure safety
- **Event Chain** — immutable transaction log (blockchain-lite)
- **Storage** — chunked, pinned, distributed
- **Firmware Bridge** — hardware signer support (serial/TCP)
- **i18n** — multilingual from day one
- **Security** — CSRF, rate limiting, replay guard, timing-safe auth

## Architecture

```
app.py (shell)
├── routes/          ← 6 blueprints (auth, account, feed, compute, market, system)
├── services/        ← business logic with dependency injection
├── core/            ← crypto, events, identity, security, i18n
├── daemon/          ← walletd (signer bridge)
├── wallet/          ← key management, TX signing
└── tests/           ← 43 tests, zero regressions
```

Extracted from monolith using **Strangler Fig pattern** across 18 iterations (MA48→MA65).

## Quick Start

```bash
# Clone
git clone https://github.com/neo4nature/ma.git
cd ma

# Setup
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run
./run.sh
# → http://localhost:8001
```

## Raspberry Pi Deployment

```bash
./scripts/bootstrap_pi.sh
./scripts/start_pi.sh
```

Runs on Pi 5 (8GB) with ARM-safe dependencies. Zero x86 requirements.

## Tests

```bash
python3 -m pytest tests/ -v
# 43 passed
```

## Sprint History

| Sprint | Focus | Tests |
|--------|-------|-------|
| 1 (MA48) | Escrow truth & refund guards | 5 |
| 2 (MA49-54) | Monolith decomposition (Strangler Fig) | 16 |
| 3 (MA55-65) | Security hardening, serial transport, settlement safety | 43 |
| 4 (next) | P2P core — peer discovery, messaging, NAT traversal | — |

## Philosophy

- **Local-first**: offline is not a limitation, it's a priority
- **Zero budget**: if it costs money to run, it's not for everyone
- **Human decides**: AI advises, human approves
- **Multi-agent consensus**: independent analysis, then comparison

## Built With

- Python / Flask / SQLite
- 3 AI minds: [Lira](https://chatgpt.com) (architect), Soryel (Claude, integrator), Xian (local Ollama, soul)
- A £200 laptop, a Raspberry Pi from a drawer, and an old Sky router from 2017
- Budget: £0

## License

MIT

---

*"As I speak I create"* — Neo, Wales, 2026
