# backend/app/services/scanners/semgrep_scanner.py
"""
Semgrep SAST scanner wrapper.

Runs Semgrep against a local repo path and returns its findings in
Semgrep's native JSON shape. Normalization into AegisDevSec's unified
Vulnerability schema happens separately, in the findings normalizer —
this file's only job is "run the tool correctly and hand back its
raw output."
"""

from app.services.scanners.base import (
    run_scanner_subprocess,
    sanitize_repo_path,
)


def run_semgrep(repo_path: str, ruleset: str = "p/security-audit") -> list[dict]:
    """
    Run Semgrep against the given local repo path.

    Args:
        repo_path: Local filesystem path to the cloned repo to scan.
        ruleset: Semgrep ruleset to use. Defaults to the same
            "p/security-audit" pack used in AegisDevSec's own CI
            self-scan.

    Returns:
        A list of Semgrep finding dicts, exactly as Semgrep's own
        `--json` output shape defines them (each with keys like
        "check_id", "path", "start", "end", "extra", etc.).

    Raises:
        ScannerExecutionError: if Semgrep times out, isn't installed,
            exits with an unexpected code, or returns invalid JSON.
        ValueError: if repo_path contains unexpected characters.
    """
    safe_path = sanitize_repo_path(repo_path)

    command = [
        "semgrep",
        "--config",
        ruleset,
        "--json",
        "--quiet",
        "--no-git-ignore",
        safe_path,
    ]

    output = run_scanner_subprocess(command)

    # Semgrep's JSON output is an object with a top-level "results" list —
    # not a bare list itself. Guard against a malformed/unexpected shape
    # rather than assuming the key is always present.
    if not isinstance(output, dict) or "results" not in output:
        raise ValueError(
            "Unexpected Semgrep output shape — missing top-level 'results' key."
        )

    return output["results"]