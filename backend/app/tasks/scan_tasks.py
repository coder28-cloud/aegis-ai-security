# backend/app/tasks/scan_tasks.py
"""
Celery tasks that run the actual scan pipeline: three scanners,
normalized into Vulnerability rows, against a single Scan record.

Design decision: if one scanner fails (times out, crashes, etc.), the
scan still completes using whatever the other scanners found. A
partial result is more useful than no result — the failure is logged
so it's visible, but it doesn't block the other two tools' findings
from being recorded.

This module intentionally uses its own synchronous SQLAlchemy session
rather than the app's async session dependency (app.db.session) —
Celery workers run tasks synchronously, not inside an event loop, so
mixing in async DB calls here would need its own async bridge (the
same class of problem we hit in alembic/env.py). Keeping this task
fully synchronous is simpler and correct for a background worker.
"""

import logging
import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.celery_app import celery_app
from app.config import settings
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import Vulnerability
from app.services.normalizer_service import normalize_scan_results
from app.services.scanners.base import ScannerExecutionError
from app.services.scanners.semgrep_scanner import run_semgrep
from app.services.scanners.trivy_scanner import run_trivy
from app.services.scanners.trufflehog_scanner import run_trufflehog

logger = logging.getLogger(__name__)

# A separate, synchronous engine just for Celery tasks. We swap the
# async driver (postgresql+asyncpg) for the sync one (postgresql)
# that psycopg provides, since this code runs in a plain Celery
# worker thread, not an asyncio event loop.
_sync_database_url = str(settings.DATABASE_URL).replace(
    "postgresql+asyncpg://", "postgresql+psycopg://"
)
_sync_engine = create_engine(_sync_database_url)


def _run_scanner_safely(scanner_name: str, scanner_fn, repo_path: str) -> list[dict]:
    """
    Run a single scanner function, catching ScannerExecutionError so
    one tool's failure doesn't take down the whole scan. Returns an
    empty list (not a crash) on failure, and logs clearly so the
    failure is still visible.
    """
    try:
        return scanner_fn(repo_path)
    except ScannerExecutionError as exc:
        logger.error("Scanner '%s' failed during scan: %s", scanner_name, exc)
        return []


@celery_app.task(name="app.tasks.scan_tasks.run_scan", bind=True, max_retries=3)
def run_scan(self, scan_id: str, repo_path: str) -> dict:
    """
    Run all three scanners against repo_path, normalize their findings,
    and write Vulnerability rows for the given scan_id.

    Args:
        scan_id: UUID (as a string — Celery task args must be
            JSON-serializable, and uuid.UUID isn't) of the Scan row
            this task is fulfilling.
        repo_path: Local filesystem path to the already-cloned repo
            to scan.

    Returns:
        A small summary dict — counts per tool and total findings —
        useful for logging/debugging, not stored anywhere itself.
    """
    scan_uuid = uuid.UUID(scan_id)

    with Session(_sync_engine) as db:
        scan = db.get(Scan, scan_uuid)
        if scan is None:
            raise ValueError(f"Scan {scan_id} not found")

        scan.status = ScanStatus.RUNNING
        db.commit()

        semgrep_results = _run_scanner_safely("semgrep", run_semgrep, repo_path)
        trivy_results = _run_scanner_safely("trivy", run_trivy, repo_path)
        trufflehog_results = _run_scanner_safely("trufflehog", run_trufflehog, repo_path)

        normalized = normalize_scan_results(
            scan_id=scan_uuid,
            semgrep_results=semgrep_results,
            trivy_results=trivy_results,
            trufflehog_results=trufflehog_results,
        )

        for vuln_create in normalized:
            db_vuln = Vulnerability(**vuln_create.model_dump())
            db.add(db_vuln)

        scan.status = ScanStatus.COMPLETED
        db.commit()

        return {
            "scan_id": scan_id,
            "semgrep_findings": len(semgrep_results),
            "trivy_findings": len(trivy_results),
            "trufflehog_findings": len(trufflehog_results),
            "total_normalized": len(normalized),
        }