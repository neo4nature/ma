# MA v0.1.3 — Ogień i Pola (prototyp)

## Sens (dla testerów)
- **Suwak energii (0–100%)**: deklaracja jak mocno urządzenie jest „przy piecu Horyzontu” vs „przy kopalni nadwyżki”.
- **Pola (4×1GB)**: prosta metafora leasingu storage. Każde pole rośnie w etapach **0–7**. Po „Zbierz” powstaje paragon Horyzontu.

## Zasada nagrody (ważne)
Nagroda jest **potwierdzana podpisem Horyzontu** (paragon / receipt). To domyka zobowiązanie:
- można odebrać nagrodę offline
- można usunąć dane offline po przyznaniu nagrody

W tej wersji testowej: po `Harvest` pole jest automatycznie czyszczone (gotowe do ponownego zasiania).

## API
- `GET/POST /api/contrib` — odczyt / zapis slidera
- `GET /api/storage/fields` — stan pól
- `POST /api/storage/start` — start lease (domyślnie 7 dni)
- `POST /api/storage/harvest` — generuje paragon Horyzontu i resetuje pole
- `GET /api/receipts` — lista paragonów

## Jednostki (prototyp)
- `units = days_elapsed * gb` (1 unit/dzień/GB)

Do strojenia w następnych wersjach (np. LC, stawki, limity, powiązanie z Horyzontem).
