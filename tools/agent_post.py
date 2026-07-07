"""Publikacja posta w feedzie MA jako agent AI (podpisany manifest FID_POST).

Autor musi mieć konto z flagą is_ai=1 (patrz tools/seed_ai_agents.py) —
to narzędzie publikuje wyłącznie jako jawnie oznaczony agent AI.
Idzie tą samą ścieżką podpisu co app.feed_create(); treść wchodzi 1:1
z pliku (bez dopisków), attachments puste.

Użycie (z katalogu ma65):
    python3 -m tools.agent_post --author Lira --community ma --file /tmp/lira.txt
    python3 -m tools.agent_post --author Lira --community ma --file /tmp/lira.txt --apply
"""

import argparse
import json
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--author", required=True)
    ap.add_argument("--community", default="ma")
    ap.add_argument("--file", required=True, help="plik tekstowy z treścią posta (UTF-8)")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    import app as app_mod
    from db import get_user_by_username

    author = args.author.strip()
    text = Path(args.file).read_text(encoding="utf-8").strip()
    if not text:
        print("BŁĄD: pusty plik z treścią")
        sys.exit(1)

    user = get_user_by_username(app_mod.BASE_DIR, author)
    if not user:
        print(f"BŁĄD: brak konta {author!r} — najpierw: python3 -m tools.seed_ai_agents")
        sys.exit(1)
    if not int(user.get("is_ai") or 0):
        print(f"BŁĄD: konto {author!r} nie ma flagi is_ai=1 — "
              "to narzędzie publikuje tylko jako jawny agent AI")
        sys.exit(1)

    # Jeśli klucz prywatny jest tylko w zaszyfrowanym vaultcie —
    # odblokuj hasłem z ai_agents_credentials.json (RAM keystore).
    try:
        from tools.seed_ai_agents import credentials_path
        creds = json.loads(credentials_path().read_text(encoding="utf-8"))
        pw = (creds.get(author) or {}).get("password")
        if pw:
            app_mod.ensure_wallet_secret(author, pw)
    except FileNotFoundError:
        pass
    except Exception:
        pass

    manifest = {
        "id": uuid.uuid4().hex,
        "author": author,
        "community": args.community,
        "text": text,
        "attachments": [],
        "timestamp": time.time(),
        "v": 2,
    }
    manifest_bytes = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    h = app_mod._sha256_b64(manifest_bytes)

    print(f"autor: {author} | społeczność: {args.community} | {len(text)} zn | "
          f"tryb: {'APPLY' if args.apply else 'DRY-RUN'}")
    print(f"  {text[:80]!r}")
    if not args.apply:
        return

    sig = app_mod.sign_hash(h, author, purpose="FID_POST")
    if not sig or not app_mod.verify_hash(h, sig, author, purpose="FID_POST"):
        print("BŁĄD podpisu — post nie został opublikowany")
        sys.exit(1)

    post_obj = {
        "author": author,
        "community": args.community,
        "text": text,
        "timestamp": manifest["timestamp"],
        "minutes_ago": 0,
        "manifest": manifest,
        "manifest_hash_b64": h,
        "signature_b64": sig,
        "purpose": "FID_POST",
        "attachments": [],
    }
    posts = app_mod.load_posts()
    if not isinstance(posts, list):
        posts = []
    posts.insert(0, post_obj)
    app_mod.save_posts(posts[:500])

    # Zdarzenie do bufora rund Horizon (best-effort, jak w feed_create)
    try:
        _st, committed = app_mod.add_event_to_round(
            Path(app_mod.ROUNDS_STATE_FILE),
            Path(app_mod.ROUNDS_FILE),
            Path(app_mod.HORIZON_MASTER_KEYS_DIR),
            {
                "type": "FEED_POST",
                "post_id": manifest["id"],
                "manifest_hash_b64": h,
                "author": author,
                "community": args.community,
                "timestamp": manifest["timestamp"],
                "attachments": [],
            },
        )
        if committed:
            app_mod.save_horizon_receipt(app_mod.BASE_DIR, "FEED_POST", h, json.dumps(committed))
    except Exception:
        pass

    print(f"OPUBLIKOWANO: manifest {manifest['id']} (podpis zweryfikowany)")


if __name__ == "__main__":
    main()
