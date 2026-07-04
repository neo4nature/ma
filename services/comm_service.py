"""Thin comm (E2E messenger) service wrappers.

Same pattern as feed_service: the implementation lives in legacy app helpers.
"""

from __future__ import annotations


def comm_view():
    import app as legacy_app
    return legacy_app.comm()


def comm_send_money_view():
    import app as legacy_app
    return legacy_app.comm_send_money()


def comm_send_view():
    import app as legacy_app
    return legacy_app.comm_api_send()


def comm_thread_view(key):
    import app as legacy_app
    return legacy_app.comm_api_thread(key)
