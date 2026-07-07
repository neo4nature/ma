"""Import archiwalnych postów (FB → feed MA) jako podpisane manifesty FID_POST.

Wejście: JSONL, każdy wiersz: {"author": str, "community": str, "text": str,
"source_label": str (opcjonalne)}. Podpisuje kluczem użytkownika `--signer`
(domyślnie Neo) tą samą ścieżką co app.feed_create().

Użycie (z katalogu ma65):
    python3 -m tools.import_feed_posts --file /tmp/ma_feed_import.jsonl --dry-run
    python3 -m tools.import_feed_posts --file /tmp/ma_feed_import.jsonl --apply
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
    ap.add_argument("--file", required=True)
    ap.add_argument("--signer", default="Neo")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    import app as app_mod

    items = []
    with open(args.file) as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))

    print(f"pozycji w pliku: {len(items)} | signer: {args.signer} | "
          f"tryb: {'APPLY' if args.apply else 'DRY-RUN'}")

    posts = app_mod.load_posts()
    if not isinstance(posts, list):
        posts = []
    existing_texts = {(p.get("text") or "")[:80] for p in posts}

    now = time.time()
    new_posts = []
    for i, it in enumerate(items):
        text = it["text"].strip()
        author = it.get("author") or args.signer
        community = it["community"]
        source = it.get("source_label") or "archiwum FB: Anonimowi Pobudzeni"
        if author != args.signer:
            text = f"Treść: {author} (za zgodą autorki, {source})\n\n{text}"
        else:
            text = f"{text}\n\n({source})"

        if text[:80] in existing_texts:
            print(f"  [{i+1}] SKIP duplikat: {text[:50]!r}")
            continue

        manifest = {
            "id": uuid.uuid4().hex,
            "author": args.signer,
            "community": community,
            "text": text,
            "attachments": [],
            # starsze timestampy, żeby import nie przykrył świeżych postów
            "timestamp": now - (i + 1) * 3600,
            "v": 2,
        }
        manifest_bytes = json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        h = app_mod._sha256_b64(manifest_bytes)
        print(f"  [{i+1}] [{community}] {text[:60]!r} ({len(text)} zn)")
        if not args.apply:
            continue

        sig = app_mod.sign_hash(h, args.signer, purpose="FID_POST")
        if not sig or not app_mod.verify_hash(h, sig, args.signer, purpose="FID_POST"):
            print(f"      BŁĄD podpisu — pomijam")
            continue
        new_posts.append({
            "author": args.signer,
            "community": community,
            "text": text,
            "timestamp": manifest["timestamp"],
            "minutes_ago": 0,
            "manifest": manifest,
            "manifest_hash_b64": h,
            "signature_b64": sig,
            "purpose": "FID_POST",
            "attachments": [],
        })

    if args.apply and new_posts:
        posts = new_posts + posts
        posts.sort(key=lambda p: p.get("timestamp") or 0, reverse=True)
        app_mod.save_posts(posts[:500])
        print(f"zapisano {len(new_posts)} nowych postów (łącznie {min(len(posts),500)})")


if __name__ == "__main__":
    main()
