# backend/app/services/git_service.py
"""
Git service — clones a target repository at a specific commit into a
fresh local scratch directory, so scanners have a real filesystem
path to scan against.
"""

import os
import shutil
import subprocess
import uuid

from app.config import settings


class GitCloneError(Exception):
    """Raised when cloning or checking out a repository fails."""


def clone_repo_at_commit(repo_full_name: str, commit_sha: str) -> str:
    """
    Clone repo_full_name (e.g. "owner/repo") and check out commit_sha
    into a fresh directory under settings.SCAN_WORKSPACE_DIR.

    Returns the local filesystem path to the checked-out repo. The
    caller is responsible for cleaning this directory up once scanning
    is done — this function only creates it.

    Raises:
        GitCloneError: if clone or checkout fails for any reason.
    """
    os.makedirs(settings.SCAN_WORKSPACE_DIR, exist_ok=True)
    local_path = os.path.join(settings.SCAN_WORKSPACE_DIR, f"scan_{uuid.uuid4().hex}")

    token = settings.GITHUB_TOKEN.get_secret_value()
    clone_url = (
        f"https://x-access-token:{token}@github.com/{repo_full_name}.git"
        if token
        else f"https://github.com/{repo_full_name}.git"
    )

    try:
        subprocess.run(
            ["git", "clone", "--quiet", clone_url, local_path],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        subprocess.run(
            ["git", "-C", local_path, "checkout", "--quiet", commit_sha],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(local_path, ignore_errors=True)
        # Never let the token leak into a stored error message or log line.
        safe_stderr = (exc.stderr or "").replace(token, "***") if token else exc.stderr
        raise GitCloneError(
            f"Failed to clone/checkout {repo_full_name}@{commit_sha}: {safe_stderr}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(local_path, ignore_errors=True)
        raise GitCloneError(f"Git operation timed out for {repo_full_name}") from exc

    return local_path