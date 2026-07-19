"""Thin wrappers for remaining legacy/system routes.

This continues route extraction from the legacy monolith without changing
runtime behavior.
"""

from __future__ import annotations


def _login_gate():
    """Match app.require_login: redirect if no session user. Lazy import."""
    from flask import session, redirect, url_for, request
    if not session.get("username"):
        return redirect(url_for("auth.login_route", next=request.path))
    return None


def home_view():
    import app as legacy_app
    return legacy_app.home()


def media_index_view():
    import app as legacy_app
    return legacy_app.media_index()


def media_new_view():
    import app as legacy_app
    return legacy_app.media_new()


def media_create_view():
    import app as legacy_app
    return legacy_app.media_create()


def api_chain_head_view():
    import app as legacy_app
    return legacy_app.api_chain_head()


def api_chain_events_view():
    gate = _login_gate()
    if gate is not None:
        return gate
    import app as legacy_app
    return legacy_app.api_chain_events()


def api_chain_import_view():
    import app as legacy_app
    return legacy_app.api_chain_import()


def api_receipts_view():
    import app as legacy_app
    return legacy_app.api_receipts()



def story_view():
    import app as legacy_app
    from flask import render_template
    return render_template("story.html", me=legacy_app.current_user())
