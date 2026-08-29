# backend/app/schemas/scan.py
"""
Pydantic schemas for Scan entity.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.scan import ScanStatus


class ScanCreate(BaseModel):
    """
    Schema for creating a new scan (e.g. from a verified GitHub webhook).
    """

    repo_full_name: str
    commit_sha: str
    triggered_by: uuid.UUID | None = None


class ScanRead(BaseModel):
    """
    Schema for returning scan information.
    """

    id: uuid.UUID
    repo_full_name: str
    commit_sha: str
    triggered_by: uuid.UUID | None = None
    status: ScanStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)