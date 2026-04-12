from flask import Blueprint

from services.auth_service import (
    register_view,
    login_view,
    fid_challenge_view,
    fid_verify_view,
    fid_login_wallet_view,
    logout_view,
)

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register_route():
    return register_view()


@auth_bp.route("/login", methods=["GET", "POST"])
def login_route():
    return login_view()


@auth_bp.route("/fid/challenge", methods=["POST"])
def fid_challenge_route():
    return fid_challenge_view()


@auth_bp.route("/fid/verify", methods=["POST"])
def fid_verify_route():
    return fid_verify_view()


@auth_bp.route("/fid/login_wallet", methods=["POST"])
def fid_login_wallet_route():
    return fid_login_wallet_view()


@auth_bp.route("/logout")
def logout_route():
    return logout_view()
