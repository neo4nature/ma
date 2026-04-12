from flask import Blueprint

from services.market_storage_service import (
    market_view,
    market_create_view,
    api_pool_status_view,
    api_pool_ping_view,
    api_pricing_view,
    storage_index_view,
    storage_upload_view,
    storage_chunk_view,
    storage_assemble_index_view,
    storage_assemble_create_view,
    storage_assemble_view_view,
    storage_stream_view,
)

market_storage_bp = Blueprint("market_storage", __name__)

@market_storage_bp.route("/market", endpoint="market")
def market_route():
    return market_view()

@market_storage_bp.route("/market/create", methods=["POST"], endpoint="market_create")
def market_create_route():
    return market_create_view()

@market_storage_bp.route("/api/pool/status", endpoint="api_pool_status")
def api_pool_status_route():
    return api_pool_status_view()

@market_storage_bp.route("/api/pool/ping", methods=["POST"], endpoint="api_pool_ping")
def api_pool_ping_route():
    return api_pool_ping_view()

@market_storage_bp.route("/api/pricing", methods=["GET", "POST"], endpoint="api_pricing")
def api_pricing_route():
    return api_pricing_view()

@market_storage_bp.route("/storage", endpoint="storage_index")
def storage_index_route():
    return storage_index_view()

@market_storage_bp.route("/storage/upload", methods=["POST"], endpoint="storage_upload")
def storage_upload_route():
    return storage_upload_view()

@market_storage_bp.route("/api/blob/chunk/<sha256_hex>", endpoint="api_blob_chunk")
@market_storage_bp.route("/storage/chunk/<sha256_hex>", endpoint="storage_chunk")
def storage_chunk_route(sha256_hex: str):
    return storage_chunk_view(sha256_hex)

@market_storage_bp.route("/storage/assemble", endpoint="storage_assemble_index")
def storage_assemble_index_route():
    return storage_assemble_index_view()

@market_storage_bp.route("/storage/assemble/create", methods=["POST"], endpoint="storage_assemble_create")
def storage_assemble_create_route():
    return storage_assemble_create_view()

@market_storage_bp.route("/storage/assemble/<assembly_id>", endpoint="storage_assemble_view")
def storage_assemble_view_route(assembly_id: str):
    return storage_assemble_view_view(assembly_id)

@market_storage_bp.route("/storage/stream/<assembly_id>", endpoint="storage_stream")
def storage_stream_route(assembly_id: str):
    return storage_stream_view(assembly_id)
