"""Showroom B2B (Workwear/BHP) front tests.

Covers:
- /showroom page renders publicly (no login)
- /api/showroom/products: empty DB ok, fixtures, category/q filters,
  pagination, description parsing (sku/deep_link/category/unit)
- /api/showroom/categories: labels + counts
- non-rawpol and non-ACTIVE listings invisible
- integration: product from the API feeds POST /api/quotes/create -> 201
"""

from __future__ import annotations

import importlib
import math
import os
import sys


def _load_app(tmp_path):
    os.environ["MA_DATA_DIR"] = str(tmp_path / "data")
    os.environ["MA_SECRETS_DIR"] = str(tmp_path / "secrets")
    os.environ["MA_SIGNER_MODE"] = "SOFTWARE"
    os.environ.pop("MA_WORKER_TICK_TOKEN", None)
    for mod in ["app", "wallet.key_manager", "wallet.tx_signer", "wallet.user_keys", "core.paths"]:
        if mod in sys.modules:
            del sys.modules[mod]
    import app  # noqa: F401
    mod = importlib.reload(sys.modules["app"])
    try:
        from core.security import reset_rate_limits
        reset_rate_limits()
    except Exception:
        pass
    return mod


def _register_and_login(app_mod, client, username):
    resp = client.post(
        "/register",
        data={"username": username, "password": "pw123"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    with client.session_transaction() as sess:
        sess["username"] = username


def _desc(kategoria, ochrona, jednostka, sku, link):
    return (
        f"Kategoria: {kategoria}\n"
        f"Ochrona: {ochrona}\n"
        "Zastosowanie: []\n"
        f"Jednostka: {jednostka}\n"
        "Opakowanie: 12 szt\n"
        f"SKU: {sku}\n"
        f"Karta produktu: {link}"
    )


def _seed_listings(app_mod):
    """3 visible rawpol listings (2 categories) + 2 invisible ones."""
    import db as dbm
    base = app_mod.BASE_DIR
    dbm.create_market_listing(
        base, "rawpol-RG-100", "Marko", "Rękawice robocze RG-100",
        _desc("Rękawice", "rąk", "para", "RG-100", "https://artbhp.pl/product,RG-100,rg"),
        12.50, currency="PLN", status="ACTIVE",
    )
    dbm.create_market_listing(
        base, "rawpol-RG-200", "Marko", "Rękawice spawalnicze RG-200",
        _desc("Rękawice", "rąk", "para", "RG-200", "https://artbhp.pl/product,RG-200,rg"),
        45.00, currency="PLN", status="ACTIVE",
    )
    dbm.create_market_listing(
        base, "rawpol-HE-300", "Marko", "Hełm ochronny HE-300",
        _desc("Hełmy", "głowy", "szt", "HE-300", "https://artbhp.pl/product,HE-300,he"),
        89.99, currency="PLN", status="ACTIVE",
    )
    # invisible: not rawpol-*
    dbm.create_market_listing(
        base, "local-001", "ktos", "Drewniany triskelion",
        "zwykłe ogłoszenie", 10.0, currency="LC", status="ACTIVE",
    )
    # invisible: rawpol but not ACTIVE
    dbm.create_market_listing(
        base, "rawpol-SOLD-1", "Marko", "Buty robocze wyprzedane",
        _desc("Buty", "nóg", "para", "SOLD-1", "https://artbhp.pl/product,SOLD-1,b"),
        99.0, currency="PLN", status="SOLD",
    )


# --- 1. page ----------------------------------------------------------------

def test_showroom_page_public_no_login(tmp_path):
    app_mod = _load_app(tmp_path)
    client = app_mod.app.test_client()
    resp = client.get("/showroom")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Workwear" in html
    assert "Zapytaj o ofertę" in html


# --- 2. products API ---------------------------------------------------------

def test_products_empty_db_ok(tmp_path):
    app_mod = _load_app(tmp_path)
    client = app_mod.app.test_client()
    resp = client.get("/api/showroom/products")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["total"] == 0
    assert data["products"] == []


def test_products_listing_parsing_and_visibility(tmp_path):
    app_mod = _load_app(tmp_path)
    _seed_listings(app_mod)
    client = app_mod.app.test_client()

    resp = client.get("/api/showroom/products")
    assert resp.status_code == 200
    data = resp.get_json()
    # only 3 visible: non-rawpol and SOLD are hidden
    assert data["total"] == 3
    ids = {p["listing_id"] for p in data["products"]}
    assert "local-001" not in ids
    assert "rawpol-SOLD-1" not in ids

    by_id = {p["listing_id"]: p for p in data["products"]}
    p = by_id["rawpol-RG-100"]
    assert p["sku"] == "RG-100"
    assert p["category"] == "rąk"
    assert p["unit"] == "para"
    assert p["deep_link"] == "https://artbhp.pl/product,RG-100,rg"
    assert p["seller"] == "Marko"
    assert p["price"] == 12.50
    assert p["currency"] == "PLN"


def test_products_category_filter(tmp_path):
    app_mod = _load_app(tmp_path)
    _seed_listings(app_mod)
    client = app_mod.app.test_client()

    resp = client.get("/api/showroom/products", query_string={"category": "rąk"})
    data = resp.get_json()
    assert data["total"] == 2
    assert all(p["category"] == "rąk" for p in data["products"])

    resp = client.get("/api/showroom/products", query_string={"category": "głowy"})
    data = resp.get_json()
    assert data["total"] == 1
    assert data["products"][0]["listing_id"] == "rawpol-HE-300"

    # unknown tag -> empty, still ok
    resp = client.get("/api/showroom/products", query_string={"category": "nie_ma_takiej"})
    data = resp.get_json()
    assert data["ok"] is True
    assert data["total"] == 0


def test_products_q_filter_case_insensitive(tmp_path):
    app_mod = _load_app(tmp_path)
    _seed_listings(app_mod)
    client = app_mod.app.test_client()

    resp = client.get("/api/showroom/products", query_string={"q": "hełm"})
    data = resp.get_json()
    assert data["total"] == 1
    assert data["products"][0]["listing_id"] == "rawpol-HE-300"

    resp = client.get("/api/showroom/products", query_string={"q": "RĘKAWICE"})
    data = resp.get_json()
    assert data["total"] == 2


def test_products_pagination(tmp_path):
    app_mod = _load_app(tmp_path)
    _seed_listings(app_mod)
    client = app_mod.app.test_client()

    resp = client.get("/api/showroom/products", query_string={"per_page": 2, "page": 1})
    data = resp.get_json()
    assert data["total"] == 3
    assert data["page"] == 1
    assert data["per_page"] == 2
    assert len(data["products"]) == 2

    resp = client.get("/api/showroom/products", query_string={"per_page": 2, "page": 2})
    data = resp.get_json()
    assert data["total"] == 3
    assert len(data["products"]) == 1

    # per_page clamped to 60
    resp = client.get("/api/showroom/products", query_string={"per_page": 999})
    assert resp.get_json()["per_page"] == 60


# --- 3. categories API --------------------------------------------------------

def test_categories_labels_and_counts(tmp_path):
    app_mod = _load_app(tmp_path)
    _seed_listings(app_mod)
    client = app_mod.app.test_client()

    resp = client.get("/api/showroom/categories")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    cats = data["categories"]
    # only categories of visible listings; sorted desc by count
    assert [c["tag"] for c in cats] == ["rąk", "głowy"]
    assert cats[0] == {"tag": "rąk", "label": "Ochrona rąk", "count": 2}
    assert cats[1] == {"tag": "głowy", "label": "Ochrona głowy", "count": 1}


def test_categories_empty_db(tmp_path):
    app_mod = _load_app(tmp_path)
    client = app_mod.app.test_client()
    resp = client.get("/api/showroom/categories")
    data = resp.get_json()
    assert data["ok"] is True
    assert data["categories"] == []


# --- 4. integration: product from API -> quote create -------------------------

def test_product_to_quote_create_roundtrip(tmp_path):
    from services import b2b_quote_service as svc
    app_mod = _load_app(tmp_path)
    _seed_listings(app_mod)

    buyer = app_mod.app.test_client()
    seller = app_mod.app.test_client()
    _register_and_login(app_mod, seller, "Marko")   # seller from the feed
    _register_and_login(app_mod, buyer, "firma1")

    resp = buyer.get("/api/showroom/products", query_string={"q": "RG-100"})
    prod = resp.get_json()["products"][0]

    # qty big enough to clear Neo's bulk_only rule regardless of env config
    target = svc.BULK_ONLY_MULTIPLIER * svc.TRANSPORT_COST_PLN
    qty = max(1, int(math.ceil(target / float(prod["price"]))))

    resp = buyer.post(
        "/api/quotes/create",
        json={
            "seller_username": prod["seller"],
            "items": [{
                "sku": prod["sku"],
                "name": prod["title"],
                "qty": qty,
                "unit_price_net": prod["price"],
                "listing_id": prod["listing_id"],
            }],
            "note": "Proszę o wycenę z dostawą.",
        },
    )
    assert resp.status_code == 201, resp.get_data(as_text=True)
    quote = resp.get_json()["quote"]
    assert quote["status"] == "SENT"
    assert quote["items"][0]["sku"] == "RG-100"
    assert quote["items"][0]["listing_id"] == "rawpol-RG-100"


# --- 5. route inventory --------------------------------------------------------

def test_showroom_routes_registered(tmp_path):
    app_mod = _load_app(tmp_path)
    rules = {r.rule for r in app_mod.app.url_map.iter_rules()}
    assert "/showroom" in rules
    assert "/api/showroom/products" in rules
    assert "/api/showroom/categories" in rules


# --- 6. regression: /market must render for a logged-in user ----------------
# (market.html referenced a nonexistent 'market_buy' endpoint -> BuildError 500
#  once ACTIVE listings from another seller existed; found live 2026-07-05)

def test_market_page_renders_logged_in_with_foreign_listings(tmp_path):
    app_mod = _load_app(tmp_path)
    _seed_listings(app_mod)
    client = app_mod.app.test_client()
    _register_and_login(app_mod, client, "neo_test")
    resp = client.get("/market")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    html = resp.get_data(as_text=True)
    assert "Zapytaj o wycenę" in html          # rawpol-* -> showroom link
    assert "Napisz do sprzedawcy" in html      # non-rawpol -> comm link


def test_market_page_renders_logged_out(tmp_path):
    app_mod = _load_app(tmp_path)
    _seed_listings(app_mod)
    client = app_mod.app.test_client()
    resp = client.get("/market")
    assert resp.status_code == 200


# --- 7. thumbnails: /public_media route + thumb field in products API --------

def _seed_thumb(app_mod, listing_id):
    import db as dbm
    thumb_dir = os.path.join(app_mod.PUBLIC_MEDIA_DIR, "rawpol_thumbs")
    os.makedirs(thumb_dir, exist_ok=True)
    jpeg = b"\xff\xd8\xff\xe0" + b"\x00" * 16 + b"\xff\xd9"
    with open(os.path.join(thumb_dir, "test.jpg"), "wb") as fh:
        fh.write(jpeg)
    conn = dbm.connect(app_mod.BASE_DIR)
    conn.execute(
        "UPDATE market_listings SET thumb_path=? WHERE listing_id=?",
        ("rawpol_thumbs/test.jpg", listing_id),
    )
    conn.commit()
    conn.close()
    return jpeg


def test_public_media_serves_thumb(tmp_path):
    app_mod = _load_app(tmp_path)
    _seed_listings(app_mod)
    jpeg = _seed_thumb(app_mod, "rawpol-RG-100")
    client = app_mod.app.test_client()
    resp = client.get("/public_media/rawpol_thumbs/test.jpg")
    assert resp.status_code == 200
    assert resp.data == jpeg


def test_public_media_rejects_traversal_and_missing(tmp_path):
    app_mod = _load_app(tmp_path)
    client = app_mod.app.test_client()
    assert client.get("/public_media/../ma.db").status_code == 404
    assert client.get("/public_media/rawpol_thumbs/nope.jpg").status_code == 404


def test_products_api_thumb_field(tmp_path):
    app_mod = _load_app(tmp_path)
    _seed_listings(app_mod)
    _seed_thumb(app_mod, "rawpol-RG-100")
    client = app_mod.app.test_client()
    data = client.get("/api/showroom/products").get_json()
    by_id = {p["listing_id"]: p for p in data["products"]}
    assert by_id["rawpol-RG-100"]["thumb"] == "/public_media/rawpol_thumbs/test.jpg"
    assert by_id["rawpol-RG-200"]["thumb"] is None
