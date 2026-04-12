"""Thin feed service wrappers.

This continues the route extraction from app.py without changing runtime
behavior. The implementation still lives in legacy app helpers.
"""

from __future__ import annotations


def timeline_view():
    import app as legacy_app
    return legacy_app.timeline()


def feed_view():
    import app as legacy_app
    return legacy_app.feed()


def feed_attach_view():
    import app as legacy_app
    return legacy_app.feed_attach()


def feed_create_view():
    import app as legacy_app
    return legacy_app.feed_create()
