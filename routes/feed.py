from flask import Blueprint

from services.feed_service import (
    timeline_view,
    feed_view,
    feed_attach_view,
    feed_create_view,
)

feed_bp = Blueprint("feed", __name__)


@feed_bp.route("/timeline")
def timeline_route():
    return timeline_view()


@feed_bp.route("/feed")
def feed_route():
    return feed_view()


@feed_bp.route("/feed/attach", methods=["POST"])
def feed_attach_route():
    return feed_attach_view()


@feed_bp.route("/feed/create", methods=["POST"])
def feed_create_route():
    return feed_create_view()
