"""Thin wrappers for remaining legacy/system routes.

This continues route extraction from the legacy monolith without changing
runtime behavior.
"""

from __future__ import annotations


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
