"""Fetch lightweight product thumbnails for rawpol-* listings (Workwear Pilot).

Strategy: artBHP's AJAX search (`?do=ajaxrequest` GETSEARCHKTMLIST) returns
product-group entries with a ready-made ~6 KB `_small` CDN thumbnail and the
group name. A match counts only when the group name equals the query
(case-insensitive) — no fuzzy hits.

Query resolution per SKU (each step verified, results cached so variant
listings share lookups and files):
  1. full SKU
  2. strip trailing `_segment`s (3M-DSCIE-310W_180 -> 3M-DSCIE-310W)
  3. strip up to 4 trailing chars, min 4 left (FLABBL -> FLAB, K-VISPL -> K-VIS)

Thumbs land in PUBLIC_MEDIA_DIR/rawpol_thumbs/ (one file per unique CDN photo,
shared by variants) and market_listings.thumb_path is set so /showroom and
/market pick them up.

Defaults are safe: dry-run (no network) unless --execute is passed.

Usage:
  python3 tools/fetch_rawpol_thumbs.py --limit 20 --execute
  python3 tools/fetch_rawpol_thumbs.py --execute            # full batch
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import time

DEFAULT_MA_DB = "runtime/ma.db"
DEFAULT_MEDIA_DIR = "runtime/public_media"
THUMB_SUBDIR = "rawpol_thumbs"
UA = "Mozilla/5.0 (X11; Linux x86_64) MA-Showroom-ThumbFetcher"
SEARCH_URL = "https://artbhp.pl/index.php?do=ajaxrequest"

GROUP_RE = re.compile(
    r'<img src="(https://st\d+\.artbhp\.pl/img/thumbs/[^"]+_small\.jpg)"/>'
    r'\s*<div class="tekst">([^<]+)<',
    re.S,
)
MIN_QUERY_LEN = 4
MAX_CHAR_STRIPS = 4


def parse_sku(description: str | None) -> str | None:
    for line in (description or "").splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() == "sku":
            return value.strip() or None
    return None


def candidates(conn: sqlite3.Connection, refresh: bool) -> list[sqlite3.Row]:
    sql = (
        "SELECT listing_id, description, thumb_path FROM market_listings "
        "WHERE status='ACTIVE' AND listing_id LIKE 'rawpol-%'"
    )
    if not refresh:
        sql += " AND (thumb_path IS NULL OR thumb_path = '')"
    sql += " ORDER BY listing_id"
    return conn.execute(sql).fetchall()


def query_chain(sku: str) -> list[str]:
    """Ordered queries to try: full SKU, `_` strips, then char strips."""
    chain = [sku]
    q = sku
    while "_" in q:
        q = q.rsplit("_", 1)[0]
        if len(q) >= MIN_QUERY_LEN:
            chain.append(q)
    base = chain[-1]
    for i in range(1, MAX_CHAR_STRIPS + 1):
        q = base[:-i]
        if len(q) < MIN_QUERY_LEN:
            break
        chain.append(q)
    return chain


class ThumbFetcher:
    def __init__(self, session, out_dir: str, delay: float):
        self.session = session
        self.out_dir = out_dir
        self.delay = delay
        self.search_cache: dict[str, str | None] = {}
        self.file_cache: dict[str, str | None] = {}

    def search(self, query: str) -> str | None:
        """Return verified `_small` thumb URL for query, or None."""
        key = query.lower()
        if key in self.search_cache:
            return self.search_cache[key]
        url = None
        try:
            resp = self.session.post(
                SEARCH_URL,
                data={
                    "hname": "PRODUCTS",
                    "fname": "GETSEARCHKTMLIST",
                    "request": query,
                    "maxProducts": 4,
                    "maxOthers": 3,
                    "filter": "",
                },
                timeout=25,
            )
            html = json.loads(resp.text)
            for thumb_url, name in GROUP_RE.findall(html):
                if name.strip().lower() == key:
                    url = thumb_url
                    break
        except Exception:
            pass
        self.search_cache[key] = url
        time.sleep(self.delay)
        return url

    def download(self, thumb_url: str) -> str | None:
        """Download thumb once per unique URL, return relpath or None."""
        if thumb_url in self.file_cache:
            return self.file_cache[thumb_url]
        rel = None
        try:
            resp = self.session.get(thumb_url, timeout=25)
            if resp.status_code == 200 and resp.content[:3] == b"\xff\xd8\xff":
                fname = re.sub(r"[^A-Za-z0-9_.-]", "_", thumb_url.rsplit("/", 1)[-1])
                with open(os.path.join(self.out_dir, fname), "wb") as fh:
                    fh.write(resp.content)
                rel = f"{THUMB_SUBDIR}/{fname}"
        except Exception:
            pass
        self.file_cache[thumb_url] = rel
        return rel

    def resolve(self, sku: str) -> tuple[str, str | None]:
        """Return (status, thumb relpath)."""
        for query in query_chain(sku):
            thumb_url = self.search(query)
            if thumb_url:
                rel = self.download(thumb_url)
                return ("ok", rel) if rel else ("thumb_bad", None)
        return "not_found", None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DEFAULT_MA_DB)
    ap.add_argument("--media-dir", default=DEFAULT_MEDIA_DIR)
    ap.add_argument("--limit", type=int, default=0, help="0 = all")
    ap.add_argument("--delay", type=float, default=0.5, help="seconds between search requests")
    ap.add_argument("--refresh", action="store_true", help="also re-fetch listings that already have a thumb")
    ap.add_argument("--execute", action="store_true", help="actually fetch + write (default: dry-run listing)")
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    rows = candidates(conn, args.refresh)
    if args.limit:
        rows = rows[: args.limit]
    print(f"candidates: {len(rows)} (refresh={args.refresh})")

    if not args.execute:
        for r in rows[:10]:
            sku = parse_sku(r["description"])
            print(f"  DRY {r['listing_id']} sku={sku} chain={query_chain(sku) if sku else '-'}")
        if len(rows) > 10:
            print(f"  ... and {len(rows) - 10} more")
        print("dry-run only — pass --execute to fetch")
        return

    import requests

    session = requests.Session()
    session.headers["User-Agent"] = UA
    out_dir = os.path.join(args.media_dir, THUMB_SUBDIR)
    os.makedirs(out_dir, exist_ok=True)
    fetcher = ThumbFetcher(session, out_dir, args.delay)

    stats: dict[str, int] = {}
    t0 = time.time()
    for i, r in enumerate(rows, 1):
        sku = parse_sku(r["description"])
        if not sku:
            stats["no_meta"] = stats.get("no_meta", 0) + 1
            continue
        status, rel = fetcher.resolve(sku)
        stats[status] = stats.get(status, 0) + 1
        if status == "ok" and rel:
            conn.execute(
                "UPDATE market_listings SET thumb_path=?, updated_ts=? WHERE listing_id=?",
                (rel, time.time(), r["listing_id"]),
            )
            conn.commit()
        if i % 25 == 0 or i == len(rows):
            el = time.time() - t0
            print(f"[{i}/{len(rows)}] {el:.0f}s stats={stats} cache={len(fetcher.search_cache)}", flush=True)

    print(f"DONE in {time.time() - t0:.0f}s stats={stats}")


if __name__ == "__main__":
    main()
