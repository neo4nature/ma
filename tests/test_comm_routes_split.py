"""Comm (E2E messenger) route tests + route-inventory truncation guard.

The messenger was born 2025-12-30, lived until ma47 and silently died in
ma48_patched when app.py lost 853 lines (26 routes) during a patch. Nobody
noticed for three months because no test watched the route inventory.
These tests bring the messenger back and make sure that failure mode is loud.
"""

import importlib
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
    return importlib.reload(sys.modules["app"])


def _register_and_login(app_mod, client, username):
    resp = client.post(
        "/register",
        data={"username": username, "password": "pw123"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    with client.session_transaction() as sess:
        sess["username"] = username


def test_comm_routes_registered(tmp_path):
    app_mod = _load_app(tmp_path)
    rules = {r.rule for r in app_mod.app.url_map.iter_rules()}
    assert "/comm" in rules
    assert "/comm/send" in rules
    assert "/comm/send_money" in rules
    assert "/comm/thread/<path:key>" in rules


def test_comm_requires_login(tmp_path):
    app_mod = _load_app(tmp_path)
    client = app_mod.app.test_client()
    resp = client.get("/comm", follow_redirects=False)
    assert resp.status_code in (301, 302)


def test_comm_e2e_send_and_thread_roundtrip(tmp_path):
    app_mod = _load_app(tmp_path)
    client = app_mod.app.test_client()

    client2 = app_mod.app.test_client()
    _register_and_login(app_mod, client2, "lira")
    _register_and_login(app_mod, client, "neo")

    resp = client.post(
        "/comm/send",
        json={"receiver": "lira", "body": "Witaj z powrotem, komunikatorze"},
        follow_redirects=False,
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    msgs = data["messages"]
    assert len(msgs) == 1
    assert msgs[0]["sender"] == "neo"
    assert msgs[0]["receiver"] == "lira"
    assert msgs[0]["body"] == "Witaj z powrotem, komunikatorze"
    # stored ciphertext, decrypted only for the pair
    assert msgs[0]["encrypted"] is True

    # thread endpoint returns the same decrypted view
    resp2 = client.get("/comm/thread/neo__lira")
    assert resp2.status_code == 200
    data2 = resp2.get_json()
    assert data2["thread_key"] == "lira::neo"
    assert data2["messages"][0]["body"] == "Witaj z powrotem, komunikatorze"

    # comm page renders with the conversation
    resp3 = client.get("/comm")
    assert resp3.status_code == 200
    assert "comm" in resp3.get_data(as_text=True).lower()


def test_comm_send_guards(tmp_path):
    app_mod = _load_app(tmp_path)
    client = app_mod.app.test_client()
    _register_and_login(app_mod, client, "neo")

    resp = client.post("/comm/send", json={"receiver": "", "body": "x"})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "missing_receiver"

    resp2 = client.post("/comm/send", json={"receiver": "neo", "body": "x"})
    assert resp2.status_code == 400
    assert resp2.get_json()["error"] == "cannot_message_self"


def test_route_inventory_guard(tmp_path):
    """Silent-truncation guard.

    ma47 -> ma48 lost 26 routes and nothing screamed. If a critical route
    disappears or the total count drops below the known floor, scream here.
    """
    app_mod = _load_app(tmp_path)
    rules = {r.rule for r in app_mod.app.url_map.iter_rules()}

    critical = {
        "/",
        "/login",
        "/register",
        "/logout",
        "/feed",
        "/timeline",
        "/market",
        "/storage",
        "/comm",
        "/comm/send",
        "/comm/send_money",
        "/comm/thread/<path:key>",
        "/api/chain/head",
        "/api/chain/events",
        "/api/receipts",
    }
    missing = critical - rules
    assert not missing, f"Critical routes vanished: {sorted(missing)}"

    # Known floor at MA65 + comm resurrection (static route excluded by Flask? it's included).
    assert len(rules) >= 44, f"Route inventory shrank to {len(rules)} — check for file truncation"
