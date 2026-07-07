"""Testy przypiętych postów: sort na górę feedu + badge Fundament."""

import sys
import uuid


def _mk_post(author, text, pinned=False):
    p = {
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
    if pinned:
        p["pinned"] = True
    return p


def test_pinned_post_sorts_to_top_with_badge(client, monkeypatch):
    posts = [
        _mk_post("HumanTester", "zwykly post najnowszy"),
        _mk_post("Lira", "manifest fundamentowy", pinned=True),
    ]
    # patch przez sys.modules["app"] — patrz komentarz w test_ai_agents.py
    monkeypatch.setattr(sys.modules["app"], "load_posts", lambda: posts)
    resp = client.get("/feed?mode=21")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert html.count('class="pinned-badge"') == 1
    assert html.index("manifest fundamentowy") < html.index("zwykly post najnowszy")


def test_no_pinned_badge_without_flag(client, monkeypatch):
    posts = [_mk_post("HumanTester", "zwykly post")]
    monkeypatch.setattr(sys.modules["app"], "load_posts", lambda: posts)
    resp = client.get("/feed?mode=21")
    assert resp.status_code == 200
    assert resp.data.decode("utf-8").count('class="pinned-badge"') == 0
