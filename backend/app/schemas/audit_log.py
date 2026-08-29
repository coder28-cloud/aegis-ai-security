# backend/app/schemas/audit_log.py
"""
Pydantic schemas for AuditLog entity.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AuditLogCreate(BaseModel):
    """
    Schema for creating a new audit log entry (internal use only —
    never exposed as a public API input).
    """

    actor: str
    action: str
    target_type: str | None = None
    target_id: uuid.UUID | None = None
    log_metadata: dict | None = None


class AuditLogRead(BaseModel):
    """
    Schema for returning audit log information.
    """

    id: uuid.UUID
    actor: str
    action: str
    target_type: str | None = None
    target_id: uuid.UUID | None = None
    log_metadata: dict | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)