# backend/app/api/v1/router.py
"""
V1 API router aggregating all resource sub-routers.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import auth, webhooks

api_router = APIRouter(prefix="/v1")
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(webhooks.router, prefix="/webhooks", tags=["Webhooks"])