from flask import Blueprint

from services.comm_service import (
    comm_view,
    comm_send_money_view,
    comm_send_view,
    comm_thread_view,
    comm_device_pair_view,
    comm_ready_envelope_view,
)

comm_bp = Blueprint("comm_routes", __name__)


@comm_bp.route("/comm")
def comm_route():
    return comm_view()


@comm_bp.route("/comm/send_money", methods=["POST"])
def comm_send_money_route():
    return comm_send_money_view()


@comm_bp.route("/comm/send", methods=["POST"])
def comm_send_route():
    return comm_send_view()


@comm_bp.route("/comm/thread/<path:key>", methods=["GET"])
def comm_thread_route(key):
    return comm_thread_view(key)


@comm_bp.route("/comm/device/pair", methods=["POST"])
def comm_device_pair_route():
    return comm_device_pair_view()


@comm_bp.route("/comm/envelope", methods=["POST"])
def comm_ready_envelope_route():
    return comm_ready_envelope_view()
