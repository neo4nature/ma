import os


def test_cross_origin_post_is_rejected(client):
    resp = client.post('/fid/challenge', json={'username': 'neo'}, headers={'Origin': 'https://evil.example'})
    assert resp.status_code == 403


def test_same_origin_post_still_works(client):
    resp = client.post('/fid/challenge', json={'username': 'neo'}, headers={'Origin': 'http://localhost'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['ok'] is True
    assert 'challenge' in data


def test_rate_limit_can_trigger_with_override(monkeypatch, client):
    monkeypatch.setenv('MA_RATE_LIMIT_OVERRIDE', '2')
    # first two pass
    assert client.post('/fid/challenge', json={'username': 'neo'}).status_code == 200
    assert client.post('/fid/challenge', json={'username': 'neo'}).status_code == 200
    third = client.post('/fid/challenge', json={'username': 'neo'})
    assert third.status_code == 429
    assert third.get_json()['error'] == 'rate_limited'
