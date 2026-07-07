"""Przypinanie postów w feedzie MA (fundamenty na górze feedu).

Flaga `pinned` żyje w post_obj POZA podpisanym manifestem — podpisy i hashe
pozostają nietknięte, tak samo jak attachments dokładane po imporcie.

Użycie (z katalogu ma65):
    python3 -m tools.pin_post --list
    python3 -m tools.pin_post --match "Czy wiesz kto jest" --apply
    python3 -m tools.pin_post --match "Czy wiesz kto jest" --unpin --apply
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--match", help="prefiks/fragment początku tekstu posta (dopasowanie w text[:120])")
    ap.add_argument("--unpin", action="store_true")
    ap.add_argument("--list", action="store_true", help="pokaż przypięte posty")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    import app as app_mod

    posts = app_mod.load_posts()
    if not isinstance(posts, list):
        print("BŁĄD: brak postów")
        sys.exit(1)

    if args.list:
        for p in posts:
            if p.get("pinned"):
                print(f"[PIN] {p.get('author')}: {(p.get('text') or '')[:70]!r}")
        return

    if not args.match:
        print("BŁĄD: podaj --match albo --list")
        sys.exit(1)

    hits = [p for p in posts if args.match in (p.get("text") or "")[:120]]
    if len(hits) != 1:
        print(f"BŁĄD: dopasowano {len(hits)} postów (wymagany dokładnie 1):")
        for p in hits[:5]:
            print(f"  - {p.get('author')}: {(p.get('text') or '')[:70]!r}")
        sys.exit(1)

    post = hits[0]
    action = "ODEPNIJ" if args.unpin else "PRZYPNIJ"
    print(f"{action}: {post.get('author')}: {(post.get('text') or '')[:70]!r} | "
          f"tryb: {'APPLY' if args.apply else 'DRY-RUN'}")
    if not args.apply:
        return

    if args.unpin:
        post.pop("pinned", None)
    else:
        post["pinned"] = True
    app_mod.save_posts(posts)
    print("zapisano")


if __name__ == "__main__":
    main()
