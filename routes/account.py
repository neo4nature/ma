from flask import Blueprint

from services.account_service import (
    account_view,
    account_preferences_view,
    account_security_view as account_security_service_view,
    account_recovery_view,
    account_keys_rotate_view,
)

account_bp = Blueprint("account_routes", __name__)


@account_bp.route("/account", methods=["GET", "POST"])
def account_route():
    return account_view()


@account_bp.route("/account/preferences", methods=["GET", "POST"])
def account_preferences_route():
    return account_preferences_view()


@account_bp.route("/account/security", methods=["GET"])
def account_security_route():
    return account_security_service_view()


@account_bp.route("/api/account/recovery", methods=["GET", "POST"])
def account_recovery_route():
    return account_recovery_view()


@account_bp.route("/api/account/keys/rotate", methods=["POST"])
def account_keys_rotate_route():
    return account_keys_rotate_view()
