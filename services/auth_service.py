"""Thin auth service wrappers.

This continues the route extraction from app.py without changing runtime
behavior. The implementation still lives in legacy app helpers.
"""

from __future__ import annotations


def register_view():
    import app as legacy_app
    return legacy_app.register()


def login_view():
    import app as legacy_app
    return legacy_app.login()


def fid_challenge_view():
    import app as legacy_app
    return legacy_app.fid_challenge()


def fid_verify_view():
    import app as legacy_app
    return legacy_app.fid_verify()


def fid_login_wallet_view():
    import app as legacy_app
    return legacy_app.fid_login_wallet()


def logout_view():
    import app as legacy_app
    return legacy_app.logout()
