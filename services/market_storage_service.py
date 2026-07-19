"""Thin market/storage service wrappers.

This continues route extraction from app.py without changing runtime behavior.
"""
from __future__ import annotations


def _login_gate():
    """Reuse app.require_login semantics via the session.

    Returns a Flask response (redirect) if user not logged in, else None.
    Lazy import avoids circular import with app.py.
    """
    from flask import session, redirect, url_for, request
    if not session.get("username"):
        return redirect(url_for("auth.login_route", next=request.path))
    return None


def market_view():
    import app as legacy_app
    return legacy_app.market()


def market_create_view():
    import app as legacy_app
    return legacy_app.market_create()


def api_pool_status_view():
    gate = _login_gate()
    if gate is not None:
        return gate
    import app as legacy_app
    return legacy_app.api_pool_status()


def api_pool_ping_view():
    import app as legacy_app
    return legacy_app.api_pool_ping()


def api_pricing_view():
    import app as legacy_app
    return legacy_app.api_pricing()


def storage_index_view():
    import app as legacy_app
    return legacy_app.storage_index()


def storage_upload_view():
    import app as legacy_app
    return legacy_app.storage_upload()


def storage_chunk_view(sha256_hex: str):
    gate = _login_gate()
    if gate is not None:
        return gate
    import app as legacy_app
    return legacy_app.storage_chunk(sha256_hex)


def storage_assemble_index_view():
    import app as legacy_app
    return legacy_app.storage_assemble_index()


def storage_assemble_create_view():
    import app as legacy_app
    return legacy_app.storage_assemble_create()


def storage_assemble_view_view(assembly_id: str):
    import app as legacy_app
    return legacy_app.storage_assemble_view(assembly_id)


def storage_stream_view(assembly_id: str):
    import app as legacy_app
    return legacy_app.storage_stream(assembly_id)
