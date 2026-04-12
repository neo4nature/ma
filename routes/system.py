from flask import Blueprint

from services.system_service import (
    home_view,
    media_index_view,
    media_new_view,
    media_create_view,
    api_chain_head_view,
    api_chain_events_view,
    api_chain_import_view,
    api_receipts_view,
    story_view,
)

system_bp = Blueprint("system_routes", __name__)


@system_bp.route("/", endpoint="home")
def home_route():
    return home_view()


@system_bp.route("/media", endpoint="media_index")
def media_index_route():
    return media_index_view()


@system_bp.route("/media/new", endpoint="media_new")
def media_new_route():
    return media_new_view()


@system_bp.route("/media/create", methods=["POST"], endpoint="media_create")
def media_create_route():
    return media_create_view()


@system_bp.route("/api/chain/head", endpoint="api_chain_head")
def api_chain_head_route():
    return api_chain_head_view()


@system_bp.route("/api/chain/events", endpoint="api_chain_events")
def api_chain_events_route():
    return api_chain_events_view()


@system_bp.route("/api/chain/import", methods=["POST"], endpoint="api_chain_import")
def api_chain_import_route():
    return api_chain_import_view()


@system_bp.route("/api/receipts", endpoint="api_receipts")
def api_receipts_route():
    return api_receipts_view()


@system_bp.route("/story", endpoint="story")
def story_route():
    return story_view()
