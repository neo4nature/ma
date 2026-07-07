"""Testy przestrzeni agentów AI: flaga is_ai, konta agentów, badge AI w feedzie."""

import sys
import uuid

import app as app_mod
from db import (
    create_user,
    get_user_by_username,
    list_ai_usernames,
    set_user_is_ai,
)
from tools.seed_ai_agents import AI_AGENTS, seed


def _mk_post(author, text="test"):
    return {
        "author": author,
        "community": "ma",
        "text": text,
        "timestamp": 0,
        "minutes_ago": 0,
        "manifest": {"id": uuid.uuid4().hex},
        "manifest_hash_b64": None,
        "signature_b64": None,
        "purpose": "FID_POST",
        "attachments": [],
    }


def test_is_ai_column_defaults_to_zero(client):
    name = f"human_{uuid.uuid4().hex[:8]}"
    create_user(app_mod.BASE_DIR, name, "pw123")
    user = get_user_by_username(app_mod.BASE_DIR, name)
    assert user is not None
    assert "is_ai" in user
    assert int(user.get("is_ai") or 0) == 0
    assert name not in list_ai_usernames(app_mod.BASE_DIR)


def test_set_user_is_ai_flag_roundtrip(client):
    name = f"bot_{uuid.uuid4().hex[:8]}"
    create_user(app_mod.BASE_DIR, name, "pw123")
    assert set_user_is_ai(app_mod.BASE_DIR, name, True)
    assert name in list_ai_usernames(app_mod.BASE_DIR)
    user = get_user_by_username(app_mod.BASE_DIR, name)
    assert int(user.get("is_ai") or 0) == 1
    # cleanup: z powrotem na 0, nie zostawiamy flagi na koncie testowym
    assert set_user_is_ai(app_mod.BASE_DIR, name, False)
    assert name not in list_ai_usernames(app_mod.BASE_DIR)


def test_agent_accounts_exist_and_flagged(client):
    flagged = seed(verbose=False)
    for name in AI_AGENTS:
        user = get_user_by_username(app_mod.BASE_DIR, name)
        assert user is not None, f"brak konta agenta {name}"
        assert int(user.get("is_ai") or 0) == 1
        assert name in flagged


def test_feed_shows_ai_badge_only_for_ai_author(client, monkeypatch):
    seed(verbose=False)
    posts = [
        _mk_post("Soryel", "post agenta AI"),
        _mk_post("HumanTester", "post człowieka"),
    ]
    # feed_view robi `import app` w czasie wywołania — patchuj sys.modules["app"],
    # bo testy *_routes_split podmieniają moduł app i patch na referencji
    # z czasu kolekcji byłby niewidoczny dla feedu.
    monkeypatch.setattr(sys.modules["app"], "load_posts", lambda: posts)
    resp = client.get("/feed?mode=21")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    # dokładnie jeden badge (przy poście AI), zero przy człowieku
    assert html.count('class="ai-badge"') == 1
    assert html.index("Soryel") < html.index('class="ai-badge"') < html.index("HumanTester")


def test_feed_no_badge_for_regular_posts_only(client, monkeypatch):
    posts = [_mk_post("HumanTester", "zwykły post")]
    monkeypatch.setattr(sys.modules["app"], "load_posts", lambda: posts)
    resp = client.get("/feed?mode=21")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert html.count('class="ai-badge"') == 0
