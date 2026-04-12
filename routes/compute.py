from flask import Blueprint

from services.compute_service import (
    compute_create_view,
    compute_cancel_view,
    compute_worker_tick_view,
)

compute_bp = Blueprint('compute', __name__)


@compute_bp.route('/compute/create', methods=['POST'])
def compute_create_route():
    return compute_create_view()


@compute_bp.route('/api/compute/job/cancel', methods=['POST'])
def api_compute_job_cancel_route():
    return compute_cancel_view()


@compute_bp.route('/api/compute/worker/tick', methods=['POST'])
def api_compute_worker_tick_route():
    return compute_worker_tick_view()
