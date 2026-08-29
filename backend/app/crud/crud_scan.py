# backend/app/crud/crud_scan.py
"""
CRUD operations for Scan model.
"""

import uuid
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan, ScanStatus
from app.schemas.scan import ScanCreate


async def get_scan_by_id(db: AsyncSession, scan_id: uuid.UUID) -> Scan | None:
    """
    Fetch a scan by primary key UUID.
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    return result.scalar_one_or_none()


async def get_scans_by_user(db: AsyncSession, user_id: uuid.UUID) -> Sequence[Scan]:
    """
    Fetch all scans triggered by a specific user (self-scoped dashboard view).
    """
    result = await db.execute(
        select(Scan).where(Scan.triggered_by == user_id).order_by(Scan.created_at.desc())
    )
    return result.scalars().all()


async def get_scans_by_status(db: AsyncSession, status: ScanStatus) -> Sequence[Scan]:
    """
    Fetch all scans currently in a given status (e.g. all QUEUED scans).
    """
    result = await db.execute(select(Scan).where(Scan.status == status))
    return result.scalars().all()


async def get_all_scans(db: AsyncSession) -> Sequence[Scan]:
    """
    Fetch every scan, regardless of who triggered it (admin-only view).
    """
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()))
    return result.scalars().all()


async def create_scan(db: AsyncSession, scan_in: ScanCreate) -> Scan:
    """
    Create a new scan record, defaulting to QUEUED status.
    """
    db_scan = Scan(
        repo_full_name=scan_in.repo_full_name,
        commit_sha=scan_in.commit_sha,
        triggered_by=scan_in.triggered_by,
    )
    db.add(db_scan)
    await db.flush()
    await db.refresh(db_scan)
    return db_scan


async def update_scan_status(db: AsyncSession, scan: Scan, new_status: ScanStatus) -> Scan:
    """
    Update a scan's status (e.g. QUEUED -> RUNNING -> COMPLETED/FAILED).
    """
    scan.status = new_status
    await db.flush()
    await db.refresh(scan)
    return scan