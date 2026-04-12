from pathlib import Path


def test_home_route(client):
    resp = client.get("/")
    assert resp.status_code == 200


def test_chain_head_route(client):
    resp = client.get("/api/chain/head")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, dict)
    assert "ok" in data


def test_media_index_route(client):
    resp = client.get("/media")
    assert resp.status_code == 200


def test_receipts_route_requires_login(client):
    resp = client.get("/api/receipts")
    assert resp.status_code in (302, 401, 403)


def test_chain_import_rejects_remote_by_default(client, monkeypatch):
    monkeypatch.delenv("MA_ALLOW_CHAIN_IMPORT", raising=False)
    resp = client.post(
        "/api/chain/import",
        json={"events": []},
        environ_overrides={"REMOTE_ADDR": "10.0.0.5"},
    )
    assert resp.status_code in (302, 403)


def test_story_route(client):
    resp = client.get("/story")
    assert resp.status_code == 200
