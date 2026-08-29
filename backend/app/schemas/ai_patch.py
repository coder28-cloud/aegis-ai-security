# backend/app/schemas/ai_patch.py
"""
Pydantic schemas for AIPatch entity.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.ai_patch import PatchStatus


class AIPatchCreate(BaseModel):
    """
    Schema for creating a new AI-generated patch record.
    """

    vulnerability_id: uuid.UUID
    diff_patch: str | None = None
    llm_reasoning: str | None = None


class AIPatchRead(BaseModel):
    """
    Schema for returning AI patch information.
    """

    id: uuid.UUID
    vulnerability_id: uuid.UUID
    status: PatchStatus
    diff_patch: str | None = None
    llm_reasoning: str | None = None
    pr_url: str | None = None
    pr_number: int | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)