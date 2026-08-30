# backend/app/services/scanners/base.py
"""
Shared subprocess-execution helper for all scanner wrappers.

Every scanner (Semgrep, Trivy, TruffleHog) shells out to its own CLI
and returns JSON on stdout. This module centralizes the actual
subprocess handling — timeout, non-zero exit codes, and input
sanitization — so each individual scanner file only has to define
its own command and how to interpret its own output.
"""

import json
import re
import subprocess

from app.config import settings


class ScannerExecutionError(Exception):
    """Raised when a scanner subprocess fails, times out, or returns
    output that isn't valid JSON."""


def sanitize_repo_path(repo_path: str) -> str:
    """
    Guard against shell-injection-style input before a path is ever
    passed into a subprocess call.

    Only allows a conservative set of characters that legitimate local
    filesystem paths use. Anything else (shell metacharacters like
    `;`, `|`, `&&`, backticks, `$(...)`) is rejected outright rather
    than escaped — rejecting is safer than trying to be clever about
    escaping every edge case.
    """
    if not re.fullmatch(r"[a-zA-Z0-9_\-./\\:]+", repo_path):
        raise ValueError(f"Refusing to scan path with unexpected characters: {repo_path!r}")
    return repo_path


def run_scanner_subprocess(command: list[str]) -> dict | list:
    """
    Run a scanner CLI command and parse its stdout as JSON.

    `command` must already be a fully-formed argument list (e.g.
    ["semgrep", "--json", "--config=auto", "/path/to/repo"]) —
    never a single shell string. Using a list (not `shell=True`)
    means the OS never invokes a shell to interpret the command,
    which is what actually prevents shell injection here.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=settings.SCANNER_TIMEOUT_SECONDS,
            check=False,  # we handle the exit code ourselves below
        )
    except subprocess.TimeoutExpired as exc:
        raise ScannerExecutionError(
            f"Scanner timed out after {settings.SCANNER_TIMEOUT_SECONDS}s: {command[0]}"
        ) from exc
    except FileNotFoundError as exc:
        raise ScannerExecutionError(
            f"Scanner binary not found: {command[0]}. Is it installed in this container?"
        ) from exc

    if result.returncode not in (0, 1):
        # Convention across Semgrep/Trivy/TruffleHog: 0 = clean, 1 = findings.
        # Anything else (2+) is a real tool error, not "findings exist".
        raise ScannerExecutionError(
            f"{command[0]} exited with code {result.returncode}. stderr: {result.stderr[:500]}"
        )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ScannerExecutionError(
            f"{command[0]} did not return valid JSON. stdout: {result.stdout[:500]}"
        ) from exc