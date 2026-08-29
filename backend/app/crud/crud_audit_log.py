# backend/app/crud/crud_audit_log.py
"""
CRUD operations for AuditLog model. Write-only in practice — audit
entries are created and read, never updated or deleted.
"""

import uuid
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.schemas.audit_log import AuditLogCreate


async def create_audit_log(db: AsyncSession, log_in: AuditLogCreate) -> AuditLog:
    """
    Insert a new audit log entry. Call this from any endpoint performing
    a privileged action (role change, patch approval, false-positive override).
    """
    db_log = AuditLog(**log_in.model_dump())
    db.add(db_log)
    await db.flush()
    await db.refresh(db_log)
    return db_log


async def get_all_audit_logs(db: AsyncSession) -> Sequence[AuditLog]:
    """
    Fetch every audit log entry, most recent first (admin audit log viewer).
    """
    result = await db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()))
    return result.scalars().all()


async def get_audit_logs_by_target(db: AsyncSession, target_id: uuid.UUID) -> Sequence[AuditLog]:
    """
    Fetch audit history for a specific target entity (e.g. every action
    ever taken against a specific user or patch).
    """
    result = await db.execute(
        select(AuditLog).where(AuditLog.target_id == target_id).order_by(AuditLog.created_at.desc())
    )
    return result.scalars().all()