# backend/app/celery_app.py
"""
Celery application instance — the async task queue AegisDevSec uses
to run scans and remediation work outside the request/response cycle.
"""

from celery import Celery

from app.config import settings

celery_app = Celery(
    "aegis",
    broker=str(settings.REDIS_URL),
    backend=str(settings.REDIS_URL),
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_routes={
        "app.tasks.scan_tasks.*": {"queue": "scans"},
        "app.tasks.remediation_tasks.*": {"queue": "remediation"},
    },
)


@celery_app.task(name="app.celery_app.ping")
def ping() -> str:
    """Trivial task to verify broker/worker wiring end to end."""
    return "pong"