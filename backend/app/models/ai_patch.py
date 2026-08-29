# backend/app/models/ai_patch.py
"""
AIPatch SQLAlchemy model — an LLM-proposed remediation for a single
Vulnerability, gated behind human approval before it can open a PR.
"""

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text, UUID, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.vulnerability import Vulnerability


class PatchStatus(str, enum.Enum):
    """Lifecycle of an AI-proposed patch, from generation to merge."""

    PENDING = "PENDING"
    GENERATED = "GENERATED"
    PR_OPENED = "PR_OPENED"
    REJECTED = "REJECTED"
    MERGED = "MERGED"


class AIPatch(Base):
    """
    One AI-generated remediation attempt for a single Vulnerability.
    Reaching PR_OPENED outside the pre-approved auto-merge allowlist
    requires an explicit admin approval elsewhere in the app — this
    model only tracks state, it doesn't enforce the approval gate itself.
    """

    __tablename__ = "ai_patches"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[PatchStatus] = mapped_column(
        Enum(PatchStatus, name="patch_status", native_enum=True),
        nullable=False,
        default=PatchStatus.PENDING,
    )
    diff_patch: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    pr_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    pr_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="ai_patches")

    def __repr__(self) -> str:
        return f"<AIPatch status={self.status} vuln_id={self.vulnerability_id}>"