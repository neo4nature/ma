"""Przestrzenie agentów AI — konta Soryel/Lira/Xian z flagą is_ai=1.

Konta agentów AI ekosystemu: jawnie oznaczone, zero udawania tłumu.
Idą tą samą ścieżką co rejestracja w app.register():
    create_user() -> ensure_user_records() -> ensure_wallet_secret()

Hasła: generowane bezpiecznie (secrets.token_urlsafe), zapisywane do
<MA_SECRETS_DIR>/ai_agents_credentials.json (chmod 600). Jeśli konto już
istnieje (np. Lira z bootstrapu demo), hasła NIE zmieniamy — tylko flaga.

Użycie (z katalogu ma65):
    python3 -m tools.seed_ai_agents            # utwórz/oznacz konta
    python3 -m tools.seed_ai_agents --list     # pokaż stan kont AI
"""

import argparse
import json
import os
import secrets as _secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

AI_AGENTS = ["Soryel", "Lira", "Xian"]


def credentials_path() -> Path:
    from core.paths import secrets_dir
    return secrets_dir() / "ai_agents_credentials.json"


def seed(verbose: bool = True) -> list:
    """Utwórz/oznacz konta agentów AI. Zwraca listę kont z flagą is_ai=1."""
    import app as app_mod
    from db import (
        create_user,
        get_user_by_username,
        list_ai_usernames,
        set_user_is_ai,
    )

    base_dir = app_mod.BASE_DIR
    creds_file = credentials_path()
    creds = {}
    if creds_file.exists():
        try:
            creds = json.loads(creds_file.read_text(encoding="utf-8"))
        except Exception:
            creds = {}

    changed_creds = False
    for name in AI_AGENTS:
        if get_user_by_username(base_dir, name) is None:
            password = _secrets.token_urlsafe(24)
            create_user(base_dir, name, password)
            creds[name] = {"password": password, "created_at": time.time()}
            changed_creds = True
            # klucze (comm/wallet/horizon) + zaszyfrowany vault — jak w app.register().
            # TYLKO przy tworzeniu konta: ensure_wallet_secret kasuje priv.pem po
            # zavaultowaniu, więc ponowny ensure_user_records wygenerowałby NOWĄ
            # parę i nadpisał pub.pem — podpisy z vaulta (stary klucz) przestają
            # się weryfikować.
            app_mod.ensure_user_records([name])
            app_mod.ensure_wallet_secret(name, password)
            if verbose:
                print(f"  [+] utworzono konto: {name}")
        else:
            if verbose:
                print(f"  [=] konto istnieje: {name} (hasło i klucze bez zmian)")

        set_user_is_ai(base_dir, name, True)

    if changed_creds:
        creds_file.write_text(
            json.dumps(creds, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        try:
            os.chmod(creds_file, 0o600)
        except Exception:
            pass
        if verbose:
            print(f"hasła zapisane: {creds_file}")

    return list_ai_usernames(base_dir)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true", help="tylko pokaż stan kont AI")
    args = ap.parse_args()

    if args.list:
        import app as app_mod
        from db import list_ai_usernames
        print(f"konta AI (is_ai=1): {list_ai_usernames(app_mod.BASE_DIR)}")
        return

    flagged = seed(verbose=True)
    print(f"konta AI (is_ai=1): {flagged}")


if __name__ == "__main__":
    main()
