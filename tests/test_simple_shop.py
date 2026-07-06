"""Simple Shop Core v0.1 — pricing modes (fiat/LC/barter/free/external_link).

Spec: shared_library/SIMPLE_SHOP_CORE_SPEC_2026-07-06.md (Soryel+Lira merge).
"""

import importlib
import os
import sys


def _load_app(tmp_path):
    os.environ["MA_DATA_DIR"] = str(tmp_path / "data")
    os.environ["MA_SECRETS_DIR"] = str(tmp_path / "secrets")
    os.environ["MA_SIGNER_MODE"] = "SOFTWARE"
    os.environ.pop("MA_WORKER_TICK_TOKEN", None)
    for mod in [
        "app",
        "wallet.key_manager",
        "wallet.tx_signer",
        "wallet.user_keys",
        "core.paths",
    ]:
        if mod in sys.modules:
            del sys.modules[mod]
    import app  # noqa: F401
    return importlib.reload(sys.modules["app"])


def _client(app_mod):
    from core.security import reset_rate_limits

    reset_rate_limits()
    client = app_mod.app.test_client()
    resp = client.post("/register", data={"username": "neo", "password": "pw123"}, follow_redirects=False)
    assert resp.status_code == 302
    with client.session_transaction() as sess:
        sess["username"] = "neo"
    return client


def _create(client, **fields):
    data = {"title": "Oferta testowa", "description": "opis", "bg_mode": "auto"}
    data.update(fields)
    return client.post("/market/create", data=data, follow_redirects=False)


def _find(app_mod, title):
    listings = app_mod.list_market_listings(app_mod.BASE_DIR, status=None, limit=100)
    return next((x for x in listings if x.get("title") == title), None)


def test_fiat_base_currency(tmp_path):
    app_mod = _load_app(tmp_path)
    client = _client(app_mod)
    resp = _create(client, title="Świeca sojowa", pricing_mode="fiat", price="20", currency="GBP")
    assert resp.status_code == 302
    it = _find(app_mod, "Świeca sojowa")
    assert it and it["pricing_mode"] == "fiat"
    assert it["currency"] == "GBP" and it["price"] == 20.0
    page = client.get("/market").get_data(as_text=True)
    assert "20.00 GBP" in page
    assert "Zapytaj o zakup" not in page  # seller widzi własną ofertę bez CTA


def test_fiat_custom_currency(tmp_path):
    app_mod = _load_app(tmp_path)
    client = _client(app_mod)
    resp = _create(client, title="Chleb domowy", pricing_mode="fiat", price="3",
                   currency="CUSTOM", custom_currency="muszelki")
    assert resp.status_code == 302
    it = _find(app_mod, "Chleb domowy")
    assert it and it["currency"] == "CUSTOM"
    assert it["custom_currency_label"] == "MUSZELKI"
    page = client.get("/market").get_data(as_text=True)
    assert "MUSZELKI" in page and "CUSTOM" not in page.split("Chleb domowy", 1)[1][:400]


def test_fiat_custom_currency_invalid(tmp_path):
    app_mod = _load_app(tmp_path)
    client = _client(app_mod)
    _create(client, title="Złe muszelki", pricing_mode="fiat", price="3",
            currency="CUSTOM", custom_currency="trzy zapałki i sznurek")
    assert _find(app_mod, "Złe muszelki") is None


def test_barter_requires_exchange_description(tmp_path):
    app_mod = _load_app(tmp_path)
    client = _client(app_mod)
    _create(client, title="Barter pusty", pricing_mode="barter")
    assert _find(app_mod, "Barter pusty") is None


def test_barter_creates_with_zero_price(tmp_path):
    app_mod = _load_app(tmp_path)
    client = _client(app_mod)
    resp = _create(client, title="Sadzonki pomidorów", pricing_mode="barter",
                   exchange_description="domowy chleb albo do uzgodnienia",
                   allow_topup="do_ustalenia")
    assert resp.status_code == 302
    it = _find(app_mod, "Sadzonki pomidorów")
    assert it and it["pricing_mode"] == "barter"
    assert it["price"] == 0.0
    assert it["exchange_description"].startswith("domowy chleb")
    assert it["allow_topup"] == "do_ustalenia"
    page = client.get("/market").get_data(as_text=True)
    assert "Wymiana / barter" in page
    assert "0.00" not in page.split("Sadzonki pomidorów", 1)[1][:600]


def test_free_creates_without_price(tmp_path):
    app_mod = _load_app(tmp_path)
    client = _client(app_mod)
    resp = _create(client, title="Stare deski", pricing_mode="free",
                   exchange_description="odbiór osobisty do weekendu")
    assert resp.status_code == 302
    it = _find(app_mod, "Stare deski")
    assert it and it["pricing_mode"] == "free" and it["price"] == 0.0
    page = client.get("/market").get_data(as_text=True)
    assert "Oddam / bez ceny" in page


def test_external_link_requires_http_url(tmp_path):
    app_mod = _load_app(tmp_path)
    client = _client(app_mod)
    _create(client, title="Link bez URL", pricing_mode="external_link")
    assert _find(app_mod, "Link bez URL") is None
    _create(client, title="Link JS", pricing_mode="external_link",
            external_url="javascript:alert(1)")
    assert _find(app_mod, "Link JS") is None
    resp = _create(client, title="Farma obok", pricing_mode="external_link",
                   external_url="https://example.com/farma")
    assert resp.status_code == 302
    it = _find(app_mod, "Farma obok")
    assert it and it["external_url"] == "https://example.com/farma"
    page = client.get("/market").get_data(as_text=True)
    assert "Odwiedź" in page and 'rel="noopener nofollow"' in page


def test_affiliate_requires_disclosure(tmp_path):
    app_mod = _load_app(tmp_path)
    client = _client(app_mod)
    _create(client, title="Afiliacja bez oznaczenia", pricing_mode="external_link",
            external_url="https://example.com/x", is_affiliate="tak", disclosure_text="")
    assert _find(app_mod, "Afiliacja bez oznaczenia") is None
    resp = _create(client, title="Afiliacja jawna", pricing_mode="external_link",
                   external_url="https://example.com/x", is_affiliate="tak",
                   disclosure_text="Link partnerski — możemy otrzymać prowizję.")
    assert resp.status_code == 302
    it = _find(app_mod, "Afiliacja jawna")
    assert it and it["is_affiliate"] == 1 and "prowizję" in it["disclosure_text"]
    page = client.get("/market").get_data(as_text=True)
    assert "Link partnerski" in page


def test_quote_rejected_from_form(tmp_path):
    app_mod = _load_app(tmp_path)
    client = _client(app_mod)
    _create(client, title="Quote z formularza", pricing_mode="quote", price="10")
    assert _find(app_mod, "Quote z formularza") is None


def test_legacy_form_defaults_to_life_coin(tmp_path):
    app_mod = _load_app(tmp_path)
    client = _client(app_mod)
    resp = _create(client, title="Stary formularz", price="3.5")
    assert resp.status_code == 302
    it = _find(app_mod, "Stary formularz")
    assert it and it["pricing_mode"] == "life_coin"
    assert it["currency"] == "LC" and it["price"] == 3.5
    assert it["listing_type"] == "product"


def test_rawpol_backfill_to_quote(tmp_path):
    app_mod = _load_app(tmp_path)
    import db as db_mod
    db_mod.create_market_listing(
        app_mod.BASE_DIR,
        listing_id="rawpol-test-1",
        seller="rawpol",
        title="Rękawice testowe",
        description="SKU: TEST-1",
        price=0.0,
        currency="LC",
    )
    # ponowny start aplikacji = migracja z backfillem
    db_mod.init_db(app_mod.BASE_DIR)
    it = db_mod.get_market_listing(app_mod.BASE_DIR, "rawpol-test-1")
    assert it and it["pricing_mode"] == "quote"


def test_feed_hook_fields_saved(tmp_path):
    app_mod = _load_app(tmp_path)
    client = _client(app_mod)
    resp = _create(client, title="Rękodzieło z tagami", pricing_mode="fiat", price="15",
                   currency="PLN", listing_type="creator_space",
                   region="Toruń", tags="handmade, lokalne, prezent")
    assert resp.status_code == 302
    it = _find(app_mod, "Rękodzieło z tagami")
    assert it and it["listing_type"] == "creator_space"
    assert it["region"] == "Toruń"
    assert "handmade" in it["tags"]
