# backend/app/schemas/auth.py
"""
Pydantic schemas for authentication requests and responses.
"""

from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    """
    Schema for email/password login requests.
    """

    email: EmailStr
    password: str = Field(..., min_length=1)


class Token(BaseModel):
    """
    JWT token response structure.
    """

    access_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    """
    Contents of decoded JWT access token.
    """

    sub: str | None = None
