from app import app
from core.i18n import LANGS, t


def test_i18n_module_exposes_expected_langs():
    assert 'pl' in LANGS
    assert 'en' in LANGS


def test_t_uses_request_context_language():
    with app.test_request_context('/feed?lang=en'):
        app.preprocess_request()
        assert t('feed') == 'MA Feed'


def test_context_processor_injects_t(client):
    rv = client.get('/feed?lang=en')
    assert rv.status_code == 200
    assert b'MA Feed' in rv.data
