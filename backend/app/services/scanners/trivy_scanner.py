# backend/app/services/scanners/trivy_scanner.py
"""
Trivy SCA / container scanner wrapper.

Runs Trivy in filesystem mode against a local repo path (dependency
manifests) and returns its findings in Trivy's native JSON shape.
Normalization into AegisDevSec's unified Vulnerability schema happens
separately, in the findings normalizer.
"""

from app.services.scanners.base import (
    run_scanner_subprocess,
    sanitize_repo_path,
)


def run_trivy(repo_path: str, severity: str = "CRITICAL,HIGH,MEDIUM,LOW") -> list[dict]:
    """
    Run Trivy filesystem scan against the given local repo path.

    Args:
        repo_path: Local filesystem path to the cloned repo to scan.
        severity: Comma-separated severity levels to include. Defaults
            to all four, since filtering happens later in the
            normalizer/dashboard, not by discarding data at scan time.

    Returns:
        A list of Trivy vulnerability dicts, flattened out of Trivy's
        native nested "Results" -> "Vulnerabilities" structure.

    Raises:
        ScannerExecutionError: if Trivy times out, isn't installed,
            exits with an unexpected code, or returns invalid JSON.
        ValueError: if repo_path contains unexpected characters.
    """
    safe_path = sanitize_repo_path(repo_path)

    command = [
        "trivy",
        "filesystem",
        "--scanners",
        "vuln,secret,misconfig",
        "--severity",
        severity,
        "--format",
        "json",
        "--quiet",
        safe_path,
    ]

    output = run_scanner_subprocess(command)

    if not isinstance(output, dict):
        raise ValueError("Unexpected Trivy output shape — expected a top-level JSON object.")

    # Trivy's JSON groups findings under "Results", one entry per scanned
    # target (e.g. one per lockfile found). Each entry may or may not have
    # a "Vulnerabilities" key at all, depending on what it scanned and
    # whether anything was found there.
    findings: list[dict] = []
    for result in output.get("Results", []):
        findings.extend(result.get("Vulnerabilities", []))

    return findings