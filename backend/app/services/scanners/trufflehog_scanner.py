# backend/app/services/scanners/trufflehog_scanner.py
"""
TruffleHog secrets scanner wrapper.

Runs TruffleHog against a local repo path's git history and returns
its findings. Unlike Semgrep/Trivy, TruffleHog's JSON output is
newline-delimited (one JSON object per line, not one big JSON blob) —
this wrapper's parsing logic reflects that difference.
"""

import json

from app.services.scanners.base import (
    ScannerExecutionError,
    run_scanner_subprocess,
    sanitize_repo_path,
)


def run_trufflehog(repo_path: str, only_verified: bool = True) -> list[dict]:
    """
    Run TruffleHog against the given local repo path's git history.

    Args:
        repo_path: Local filesystem path to the cloned repo to scan.
        only_verified: If True (default), only return secrets
            TruffleHog was able to actively verify as live/real —
            this is what keeps the false-positive rate low, per
            AegisDevSec's own CI configuration.

    Returns:
        A list of TruffleHog finding dicts, one per detected secret.

    Raises:
        ScannerExecutionError: if TruffleHog times out, isn't
            installed, exits with an unexpected code, or its output
            can't be parsed line by line as JSON.
        ValueError: if repo_path contains unexpected characters.
    """
    safe_path = sanitize_repo_path(repo_path)

    command = [
        "trufflehog",
        "filesystem",
        safe_path,
        "--json",
    ]
    if only_verified:
        command.append("--only-verified")

    # TruffleHog's output isn't one JSON document — it's one JSON object
    # per line (newline-delimited JSON, sometimes called JSONL). The
    # shared run_scanner_subprocess() helper assumes a single json.loads()
    # call, which doesn't fit this shape, so TruffleHog runs the raw
    # subprocess call itself instead of reusing that helper directly.
    import subprocess

    from app.config import settings

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=settings.SCANNER_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScannerExecutionError(
            f"TruffleHog timed out after {settings.SCANNER_TIMEOUT_SECONDS}s"
        ) from exc
    except FileNotFoundError as exc:
        raise ScannerExecutionError(
            "trufflehog binary not found. Is it installed in this container?"
        ) from exc

    if result.returncode not in (0, 1):
        raise ScannerExecutionError(
            f"trufflehog exited with code {result.returncode}. stderr: {result.stderr[:500]}"
        )

    findings: list[dict] = []
    for line in result.stdout.strip().splitlines():
        if not line.strip():
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ScannerExecutionError(
                f"TruffleHog produced a non-JSON line: {line[:200]}"
            ) from exc

    return findings