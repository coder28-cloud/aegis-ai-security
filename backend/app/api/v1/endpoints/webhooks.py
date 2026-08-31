# backend/app/api/v1/endpoints/webhooks.py
"""
GitHub webhook endpoint — receives push events, verifies the request's
signature, creates a QUEUED Scan record, clones the repo at the pushed
commit, and enqueues the scan pipeline as a Celery task.
"""

import hashlib
import hmac

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.crud.crud_scan import create_scan
from app.db.session import get_db_session
from app.schemas.scan import ScanCreate
from app.services.git_service import GitCloneError, clone_repo_at_commit
from app.tasks.scan_tasks import run_scan

router = APIRouter()


def verify_github_signature(payload_body: bytes, signature_header: str | None) -> None:
    """
    Verify the X-Hub-Signature-256 header against the raw request body,
    using GITHUB_WEBHOOK_SECRET. Raises HTTPException(401) if missing
    or invalid, or 500 if the server itself has no secret configured.
    """
    secret = settings.GITHUB_WEBHOOK_SECRET.get_secret_value()
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GITHUB_WEBHOOK_SECRET is not configured on the server.",
        )
    if not signature_header:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing signature header.")

    expected = "sha256=" + hmac.new(secret.encode(), payload_body, hashlib.sha256).hexdigest()

    # Constant-time comparison — a plain `==` here would leak timing
    # information an attacker could theoretically use to forge a valid
    # signature one byte at a time. hmac.compare_digest exists exactly
    # to close that gap.
    if not hmac.compare_digest(expected, signature_header):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid signature.")


@router.post("/github", status_code=status.HTTP_202_ACCEPTED)
async def github_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Receives a GitHub push webhook and enqueues a scan.
    """
    payload_body = await request.body()
    signature_header = request.headers.get("X-Hub-Signature-256")
    verify_github_signature(payload_body, signature_header)

    payload = await request.json()

    repo_full_name = payload.get("repository", {}).get("full_name")
    commit_sha = payload.get("after")

    if not repo_full_name or not commit_sha:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload missing required 'repository.full_name' or 'after' (commit SHA) fields.",
        )

    scan = await create_scan(
        db,
        ScanCreate(repo_full_name=repo_full_name, commit_sha=commit_sha, triggered_by=None),
    )

    try:
        local_path = clone_repo_at_commit(repo_full_name, commit_sha)
    except GitCloneError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Could not clone repository: {exc}",
        )

    run_scan.delay(str(scan.id), local_path)

    return {"scan_id": str(scan.id), "status": "queued"}