# backend/app/schemas/user.py
"""
Pydantic schemas for User entity.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    """
    Schema for creating a new user.
    """

    email: EmailStr
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters long")
    full_name: str | None = Field(default=None, max_length=255)


class UserRead(BaseModel):
    """
    Schema for returning public user information.
    """

    id: uuid.UUID
    email: EmailStr
    full_name: str | None = None
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
