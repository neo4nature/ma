"""Selective import: rawpol_catalog.db -> market_listings (Workwear Pilot).

Reads the tagged Rawpol catalog (Lira repo) and inserts/updates listings in
ma65 runtime/ma.db. Selective by protection_tag — never the full 31k dump.

Defaults are safe: --dry-run is ON unless --execute is passed.
Margin default 0% (raw PLN-A price list) — final margin is Neo's decision.

Usage:
  python3 tools/import_rawpol_listings.py \
      --categories głowy,ppoż --limit 50 --seller Neo --margin 0 --execute
"""

from __future__ import annotations

import argparse
import sqlite3
import time
import uuid

DEFAULT_CATALOG = "/media/neo/Docker1/Lira/kernel/data/runtime/state/rawpol_catalog.db"
DEFAULT_MA_DB = "runtime/ma.db"

VALID_TAGS = {
    "głowy", "oczu_i_twarzy", "słuchu", "dróg_oddechowych", "rąk", "nóg",
    "ciała", "upadek_z_wysokości", "ppoż", "higiena", "branżowe",
    "wyposażenie_zakładów", "nadruki_opakowania", "nie_sklasyfikowane",
}


def build_title(row: sqlite3.Row) -> str:
    name = (_col(row, "name") or "").strip()
    brand = (row["brand"] or "").strip()
    symbol = (row["symbol"] or row["variant_base"] or "").strip()
    if name:
        parts = [name.capitalize() if name.isupper() else name, symbol or brand]
    else:
        parts = [brand]
        if symbol and symbol.upper() != brand.upper():
            parts.append(symbol)
    color = row["variant_color"]
    size = row["variant_size"]
    if color:
        parts.append(str(color).strip())
    if size:
        parts.append(f"rozm. {str(size).strip()}")
    return " ".join(p for p in parts if p) or f"SKU {row['sku']}"


def _col(row: sqlite3.Row, key: str):
    try:
        return row[key]
    except IndexError:
        return None


def build_description(row: sqlite3.Row) -> str:
    lines = []
    if row["category"]:
        lines.append(f"Kategoria: {row['category']}")
    lines.append(f"Ochrona: {row['protection_tag']}")
    if row["situation_tags"]:
        lines.append(f"Zastosowanie: {row['situation_tags']}")
    if row["unit"]:
        lines.append(f"Jednostka: {row['unit']}")
    if row["package_size"]:
        lines.append(f"Opakowanie: {row['package_size']}")
    lines.append(f"SKU: {row['sku']}")
    if row["deep_link"]:
        lines.append(f"Karta produktu: {row['deep_link']}")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--catalog", default=DEFAULT_CATALOG)
    ap.add_argument("--ma-db", default=DEFAULT_MA_DB)
    ap.add_argument("--categories", required=True,
                    help="comma-separated protection_tags, e.g. głowy,ppoż")
    ap.add_argument("--limit", type=int, default=50, help="max SKU per category")
    ap.add_argument("--seller", required=True, help="seller username in MA")
    ap.add_argument("--margin", type=float, default=0.0, help="percent added to price_net")
    ap.add_argument("--execute", action="store_true", help="actually write (default dry-run)")
    ap.add_argument("--rank-bestsellers", action="store_true",
                    help="order by kupowanoZ in-degree (requires dynamic_data table) and require availability")
    args = ap.parse_args()

    tags = [t.strip() for t in args.categories.split(",") if t.strip()]
    bad = [t for t in tags if t not in VALID_TAGS]
    if bad:
        raise SystemExit(f"unknown protection_tag(s): {bad}\nvalid: {sorted(VALID_TAGS)}")

    cat = sqlite3.connect(args.catalog)
    cat.row_factory = sqlite3.Row
    ma = sqlite3.connect(args.ma_db)

    seller_row = ma.execute("SELECT id FROM users WHERE username=?", (args.seller,)).fetchone()
    if not seller_row:
        raise SystemExit(f"seller '{args.seller}' not found in MA users")

    factor = 1.0 + args.margin / 100.0
    now = time.time()
    inserted = updated = 0

    indegree = {}
    if args.rank_bestsellers:
        import json as _json
        for (kz,) in cat.execute("SELECT kupowano_z FROM dynamic_data WHERE kupowano_z != '[]'"):
            for ref in _json.loads(kz):
                indegree[ref.lower()] = indegree.get(ref.lower(), 0) + 1
        print(f"cross-sell graph: {len(indegree)} SKU z co najmniej 1 wskazaniem")

    for tag in tags:
        if args.rank_bestsellers:
            # dynamic_data jest po symbolu rodziny; bierzemy 1 reprezentanta rodziny
            rows = cat.execute(
                """SELECT p.* FROM products p
                   JOIN dynamic_data d ON d.sku = p.symbol
                   WHERE p.protection_tag=? AND p.price_net IS NOT NULL AND p.price_net > 0
                     AND (d.stan > 0 OR d.mozna_kupowac = 1)
                   GROUP BY p.symbol""",
                (tag,),
            ).fetchall()
            rows = sorted(rows, key=lambda r: indegree.get(str(r["symbol"]).lower(), 0), reverse=True)
            rows = rows[: args.limit]
        else:
            rows = cat.execute(
                """SELECT * FROM products
                   WHERE protection_tag=? AND price_net IS NOT NULL AND price_net > 0
                   ORDER BY price_net DESC LIMIT ?""",
                (tag, args.limit),
            ).fetchall()
        print(f"[{tag}] {len(rows)} SKU")
        for row in rows:
            listing_id = f"rawpol-{row['sku']}"
            price = round(float(row["price_net"]) * factor, 2)
            title = build_title(row)
            desc = build_description(row)
            exists = ma.execute(
                "SELECT 1 FROM market_listings WHERE listing_id=?", (listing_id,)
            ).fetchone()
            if args.execute:
                if exists:
                    ma.execute(
                        """UPDATE market_listings
                           SET title=?, description=?, price=?, currency='PLN', updated_ts=?
                           WHERE listing_id=?""",
                        (title, desc, price, now, listing_id),
                    )
                else:
                    ma.execute(
                        """INSERT INTO market_listings
                             (listing_id, seller, title, description, price, currency,
                              status, created_ts, updated_ts)
                           VALUES (?,?,?,?,?,'PLN','ACTIVE',?,?)""",
                        (listing_id, args.seller, title, desc, price, now, now),
                    )
            if exists:
                updated += 1
            else:
                inserted += 1
        if not args.execute and rows:
            r = rows[0]
            print(f"  sample: {build_title(r)} — {round(float(r['price_net']) * factor, 2)} PLN")

    if args.execute:
        ma.commit()
        print(f"DONE: inserted={inserted} updated={updated}")
    else:
        print(f"DRY-RUN: would insert={inserted} update={updated} (add --execute to write)")
    ma.close()
    cat.close()


if __name__ == "__main__":
    main()
