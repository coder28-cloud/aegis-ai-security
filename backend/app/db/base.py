# backend/app/db/base.py
"""
SQLAlchemy Declarative Base for all database models.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass
