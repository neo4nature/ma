# MA v0.8 — Identity + Horizon Rounds + Story/API

Ten pakiet rozszerza v0.7 o 3 elementy:

1) **Tożsamość urządzenia** (fingerprint w UI) — host odpytuje `walletd`/"firmware" o klucz urządzenia i weryfikuje podpis attestation.
2) **Rundy Horyzontu** — każde podpisane zdarzenie trafia do bufora; co 5 zdarzeń powstaje runda z `prev_hash`, `round_hash` i podpisem Ed25519.
3) **Opowieść + API** — strona `/story` opisuje stan projektu i pokazuje endpointy API.

## Uruchomienie

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# okno 1: daemon "firmware"
python -m daemon.walletd --transport pty  # albo: --transport tcp --host 127.0.0.1 --port 4545

# okno 2: aplikacja web
export MA_SIGNER_MODE=FIRMWARE            # albo SOFTWARE
export MA_FIRMWARE_TRANSPORT=PTY          # TCP | PTY
python app.py
```

Potem wejdź w przeglądarce:
- `/` — główne kafle
- `/wallet` — tożsamość urządzenia + rundy + transakcje
- `/comm` — komunikator E2E
- `/story` — opis + API

## API

- `GET /api/status`
- `GET /api/device`
- `GET /api/users`
- `GET /api/wallet`
- `GET /api/rounds`
