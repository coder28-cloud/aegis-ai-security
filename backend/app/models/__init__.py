# backend/app/models/__init__.py
from app.models.user import User, UserRole
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import Vulnerability, ScanTool, SeverityLevel
from app.models.ai_patch import AIPatch, PatchStatus
from app.models.audit_log import AuditLog

__all__ = [
    "User",
    "UserRole",
    "Scan",
    "ScanStatus",
    "Vulnerability",
    "ScanTool",
    "SeverityLevel",
    "AIPatch",
    "PatchStatus",
    "AuditLog",
]