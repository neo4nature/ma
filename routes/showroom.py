"""Showroom B2B (Workwear/BHP) — public catalog front for the quote pilot.

Read-only catalog over `market_listings` (rawpol-* rows imported from the
supplier feed). Product metadata (SKU, category, unit, deep link) lives in
the `description` column as `key: value` lines — parsed here, not stored
in extra columns.

The showroom only *consumes* the tested B2B backend (routes/b2b_quotes.py):
quote creation, messaging and invoices happen through those endpoints.
"""

from __future__ import annotations

from pathlib import Path

from flask import Blueprint, abort, g, jsonify, render_template, request, send_file

from core.i18n import LANGS
from core.safe_fs import UnsafePath, safe_resolve_file
from db import connect, get_user_by_username, get_user_preferences


showroom_bp = Blueprint("showroom", __name__)


# Human labels (PL) for the "Ochrona:" tags found in listing descriptions.
CATEGORY_LABELS = {
    "głowy": "Ochrona głowy",
    "oczu_i_twarzy": "Ochrona oczu i twarzy",
    "słuchu": "Ochrona słuchu",
    "dróg_oddechowych": "Ochrona dróg oddechowych",
    "rąk": "Ochrona rąk",
    "nóg": "Ochrona nóg",
    "ciała": "Ochrona ciała",
    "upadek_z_wysokości": "Upadek z wysokości",
    "ppoż": "PPOŻ",
    "higiena": "Higiena",
    "branżowe": "Branżowe",
    "wyposażenie_zakładów": "Wyposażenie zakładów",
    "nadruki_opakowania": "Nadruki i opakowania",
    "nie_sklasyfikowane": "Nie sklasyfikowane",
}


def _category_label(tag: str) -> str:
    return CATEGORY_LABELS.get(tag, tag.replace("_", " ").capitalize())


def _base_dir():
    # Lazy import to avoid circular import at module load (same pattern as
    # routes/b2b_quotes.py).
    import app as legacy_app
    return legacy_app.BASE_DIR


def _parse_description(description: str | None) -> dict:
    """Parse `key: value` lines from a listing description.

    Only the first ':' splits — URLs in values (Karta produktu) stay intact.
    """
    fields: dict[str, str] = {}
    for line in (description or "").splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if key and key not in fields:
            fields[key] = value.strip()
    return {
        "sku": fields.get("sku") or None,
        "category": fields.get("ochrona") or None,
        "unit": fields.get("jednostka") or None,
        "deep_link": fields.get("karta produktu") or None,
    }


def _fetch_rawpol_rows(base_dir: str, category: str | None = None) -> list[dict]:
    """All ACTIVE rawpol-* listings, optional SQL LIKE prefilter on category.

    The LIKE filter is a coarse prefilter (substring may over-match, and '_'
    in tags is a LIKE wildcard) — callers must re-check the parsed category
    for an exact match.
    """
    sql = (
        "SELECT listing_id, seller, title, price, currency, description, thumb_path "
        "FROM market_listings "
        "WHERE status='ACTIVE' AND listing_id LIKE 'rawpol-%'"
    )
    params: list = []
    if category:
        sql += " AND description LIKE ?"
        params.append(f"%Ochrona: {category}%")
    sql += " ORDER BY title COLLATE NOCASE ASC, listing_id ASC"
    conn = connect(base_dir)
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return rows


# --- page --------------------------------------------------------------------

@showroom_bp.route("/showroom")
def showroom_page():
    """Public showroom page — browsing works without login, CTA needs it."""
    import app as legacy_app

    me = legacy_app.current_user()
    palette = (request.args.get("palette") or "").strip()
    theme = (request.args.get("theme") or "").strip()
    lang = (request.args.get("lang") or "").strip()
    me_user_id = 0

    if me:
        try:
            user = get_user_by_username(legacy_app.BASE_DIR, me) or {}
            me_user_id = int(user.get("id") or 0)
            prefs = get_user_preferences(legacy_app.BASE_DIR, me_user_id)
            if not palette:
                palette = (prefs.get("palette") or "").strip()
            if not theme:
                theme = (prefs.get("theme") or "").strip()
            if not lang:
                lang = (prefs.get("lang") or "").strip()
        except Exception:
            pass

    if not palette:
        palette = "neo"
    if theme not in ("dark", "light"):
        theme = "dark"
    if lang not in LANGS:
        lang = getattr(g, "ui_lang", "pl")

    return render_template(
        "showroom.html",
        me=me,
        me_user_id=me_user_id,
        palette=palette,
        theme=theme,
        lang=lang,
    )


# --- JSON API ------------------------------------------------------------------

@showroom_bp.route("/api/showroom/products")
def showroom_products():
    category = (request.args.get("category") or "").strip()
    q = (request.args.get("q") or "").strip()
    try:
        page = max(1, int(request.args.get("page", 1)))
    except Exception:
        page = 1
    try:
        per_page = int(request.args.get("per_page", 24))
    except Exception:
        per_page = 24
    per_page = max(1, min(60, per_page))

    rows = _fetch_rawpol_rows(_base_dir(), category=category or None)

    q_lower = q.lower()
    products = []
    for row in rows:
        meta = _parse_description(row.get("description"))
        if category and meta["category"] != category:
            continue  # LIKE prefilter over-matched — require exact tag
        if q_lower and q_lower not in (row.get("title") or "").lower():
            continue
        thumb = row.get("thumb_path")
        products.append({
            "listing_id": row["listing_id"],
            "sku": meta["sku"],
            "title": row["title"],
            "price": row["price"],
            "currency": row["currency"],
            "category": meta["category"],
            "unit": meta["unit"],
            "deep_link": meta["deep_link"],
            "seller": row["seller"],
            "thumb": f"/public_media/{thumb}" if thumb else None,
        })

    total = len(products)
    start = (page - 1) * per_page
    page_items = products[start:start + per_page]

    return jsonify({
        "ok": True,
        "total": total,
        "page": page,
        "per_page": per_page,
        "products": page_items,
    })


@showroom_bp.route("/public_media/<path:relpath>")
def public_media(relpath: str):
    """Serve files from PUBLIC_MEDIA_DIR (listing thumbnails etc.)."""
    import app as legacy_app

    try:
        path = safe_resolve_file(Path(legacy_app.PUBLIC_MEDIA_DIR), relpath)
    except (UnsafePath, ValueError):
        abort(404)
    if not path.is_file():
        abort(404)
    return send_file(str(path), max_age=86400)


@showroom_bp.route("/api/showroom/categories")
def showroom_categories():
    rows = _fetch_rawpol_rows(_base_dir())
    counts: dict[str, int] = {}
    for row in rows:
        tag = _parse_description(row.get("description"))["category"]
        if not tag:
            continue
        counts[tag] = counts.get(tag, 0) + 1

    categories = [
        {"tag": tag, "label": _category_label(tag), "count": count}
        for tag, count in counts.items()
        if count > 0
    ]
    categories.sort(key=lambda c: (-c["count"], c["label"]))
    return jsonify({"ok": True, "categories": categories})
