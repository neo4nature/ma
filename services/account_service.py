"""Thin account service wrappers.

This continues the route extraction from app.py without changing runtime
behavior. The implementation still lives in legacy app helpers.
"""

from __future__ import annotations


def account_view():
    import app as legacy_app
    return legacy_app.account()


def account_preferences_view():
    import app as legacy_app
    return legacy_app.account_preferences()


def account_security_view():
    import app as legacy_app
    return legacy_app.account_security_view()


def account_recovery_view():
    import app as legacy_app
    return legacy_app.api_account_recovery()


def account_keys_rotate_view():
    import app as legacy_app
    return legacy_app.api_account_keys_rotate()
