# backend/app/crud/crud_ai_patch.py
"""
CRUD operations for AIPatch model.
"""

import uuid
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_patch import AIPatch, PatchStatus
from app.schemas.ai_patch import AIPatchCreate


async def get_patch_by_id(db: AsyncSession, patch_id: uuid.UUID) -> AIPatch | None:
    """
    Fetch a patch by primary key UUID.
    """
    result = await db.execute(select(AIPatch).where(AIPatch.id == patch_id))
    return result.scalar_one_or_none()


async def get_patches_by_status(db: AsyncSession, status: PatchStatus) -> Sequence[AIPatch]:
    """
    Fetch all patches in a given status (e.g. all PENDING patches awaiting
    admin review).
    """
    result = await db.execute(select(AIPatch).where(AIPatch.status == status))
    return result.scalars().all()


async def create_patch(db: AsyncSession, patch_in: AIPatchCreate) -> AIPatch:
    """
    Create a new AI-generated patch record, defaulting to PENDING status.
    """
    db_patch = AIPatch(
        vulnerability_id=patch_in.vulnerability_id,
        diff_patch=patch_in.diff_patch,
        llm_reasoning=patch_in.llm_reasoning,
    )
    db.add(db_patch)
    await db.flush()
    await db.refresh(db_patch)
    return db_patch


async def update_patch_status(db: AsyncSession, patch: AIPatch, new_status: PatchStatus) -> AIPatch:
    """
    Update a patch's status. This is the function the admin approval
    endpoint will call to move a patch from PENDING/GENERATED to
    PR_OPENED or REJECTED.
    """
    patch.status = new_status
    await db.flush()
    await db.refresh(patch)
    return patch