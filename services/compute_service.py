"""Thin compute service wrappers.

This starts the extraction of compute flow out of app.py without changing
runtime behavior. The underlying logic still lives in legacy app helpers,
but routes now depend on a dedicated service module.
"""

from __future__ import annotations


def compute_create_view():
    import app as legacy_app
    return legacy_app.compute_create()


def compute_cancel_view():
    import app as legacy_app
    return legacy_app.api_compute_job_cancel()


def compute_worker_tick_view():
    import app as legacy_app
    return legacy_app.api_compute_worker_tick()
