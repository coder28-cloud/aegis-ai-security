# backend/app/services/normalizer_service.py
"""
Findings normalizer — maps each scanner's raw, tool-specific JSON
output into AegisDevSec's unified VulnerabilityCreate schema.

This is the one place in the codebase that needs to know the exact
shape of Semgrep's, Trivy's, and TruffleHog's output. Everything
downstream (CRUD, dashboard, remediation agent) only ever deals with
the normalized Vulnerability model — it never has to know which tool
a finding originally came from in terms of parsing logic.
"""

import uuid

from app.models.vulnerability import ScanTool, SeverityLevel
from app.schemas.vulnerability import VulnerabilityCreate

# Semgrep's own severity labels don't match our SeverityLevel enum at all —
# this is a deliberate, documented judgment call, not a discovered fact.
# Revisit this mapping if Semgrep's own findings turn out under- or
# over-weighted in practice once real scans are running.
_SEMGREP_SEVERITY_MAP: dict[str, SeverityLevel] = {
    "ERROR": SeverityLevel.HIGH,
    "WARNING": SeverityLevel.MEDIUM,
    "INFO": SeverityLevel.LOW,
}

# Trivy's severity strings already match our enum values almost exactly,
# except it also emits "UNKNOWN" sometimes — map that to LOW rather than
# dropping the finding, since "we don't know" shouldn't mean "we hide it".
_TRIVY_SEVERITY_MAP: dict[str, SeverityLevel] = {
    "CRITICAL": SeverityLevel.CRITICAL,
    "HIGH": SeverityLevel.HIGH,
    "MEDIUM": SeverityLevel.MEDIUM,
    "LOW": SeverityLevel.LOW,
    "UNKNOWN": SeverityLevel.LOW,
}


def normalize_semgrep_finding(finding: dict, scan_id: uuid.UUID) -> VulnerabilityCreate:
    """
    Map one raw Semgrep finding (from run_semgrep()) into a
    VulnerabilityCreate.
    """
    extra = finding.get("extra", {})
    metadata = extra.get("metadata", {})

    # Semgrep's CWE metadata is often a list like ["CWE-89: SQL Injection"],
    # not a bare code — take just the first one, and only the code portion.
    cwe_list = metadata.get("cwe", [])
    cwe_id = cwe_list[0].split(":")[0].strip() if cwe_list else None

    raw_severity = extra.get("severity", "INFO")
    severity = _SEMGREP_SEVERITY_MAP.get(raw_severity, SeverityLevel.LOW)

    return VulnerabilityCreate(
        scan_id=scan_id,
        tool=ScanTool.SEMGREP,
        rule_id=finding.get("check_id", "unknown-rule"),
        file_path=finding.get("path", "unknown"),
        line_start=finding.get("start", {}).get("line"),
        line_end=finding.get("end", {}).get("line"),
        severity=severity,
        cwe_id=cwe_id,
        cve_id=None,  # Semgrep findings are code patterns, not CVEs
        title=finding.get("check_id", "Semgrep finding"),
        description=extra.get("message"),
        raw_finding=finding,
    )


def normalize_trivy_finding(finding: dict, scan_id: uuid.UUID) -> VulnerabilityCreate:
    """
    Map one raw Trivy finding (from run_trivy()) into a
    VulnerabilityCreate.
    """
    raw_severity = finding.get("Severity", "UNKNOWN")
    severity = _TRIVY_SEVERITY_MAP.get(raw_severity, SeverityLevel.LOW)

    vuln_id = finding.get("VulnerabilityID", "unknown-cve")
    # Trivy's VulnerabilityID is the CVE for dependency findings, but for
    # misconfig findings it's an internal rule ID (e.g. "AVD-DS-0001"),
    # not a real CVE. Only treat it as a CVE if it actually looks like one.
    cve_id = vuln_id if vuln_id.upper().startswith("CVE-") else None

    pkg_name = finding.get("PkgName", "")
    title = finding.get("Title") or f"{vuln_id} in {pkg_name}" if pkg_name else vuln_id

    return VulnerabilityCreate(
        scan_id=scan_id,
        tool=ScanTool.TRIVY,
        rule_id=vuln_id,
        file_path=finding.get("PkgPath") or pkg_name or "unknown",
        line_start=None,  # Trivy findings are dependency/package-level, not line-level
        line_end=None,
        severity=severity,
        cwe_id=None,  # Trivy doesn't expose CWE directly in this output shape
        cve_id=cve_id,
        title=title,
        description=finding.get("Description"),
        raw_finding=finding,
    )


def normalize_trufflehog_finding(finding: dict, scan_id: uuid.UUID) -> VulnerabilityCreate:
    """
    Map one raw TruffleHog finding (from run_trufflehog()) into a
    VulnerabilityCreate.

    TruffleHog has no concept of severity at all — a leaked secret is
    treated as CRITICAL if actively verified as live/real, HIGH
    otherwise (e.g. if only_verified=False was used upstream and this
    is an unconfirmed candidate).
    """
    is_verified = finding.get("Verified", False)
    severity = SeverityLevel.CRITICAL if is_verified else SeverityLevel.HIGH

    detector_name = finding.get("DetectorName", "unknown-secret-type")
    file_path = (
        finding.get("SourceMetadata", {})
        .get("Data", {})
        .get("Filesystem", {})
        .get("file", "unknown")
    )

    verified_label = "verified" if is_verified else "unverified"

    return VulnerabilityCreate(
        scan_id=scan_id,
        tool=ScanTool.TRUFFLEHOG,
        rule_id=detector_name,
        file_path=file_path,
        line_start=None,
        line_end=None,
        severity=severity,
        cwe_id="CWE-798",  # "Use of Hard-coded Credentials" — applies to every secret finding
        cve_id=None,
        title=f"Hardcoded {detector_name} secret ({verified_label})",
        description=f"TruffleHog detected a {verified_label} {detector_name} secret in this file.",
        raw_finding=finding,
    )


def normalize_scan_results(
    scan_id: uuid.UUID,
    semgrep_results: list[dict],
    trivy_results: list[dict],
    trufflehog_results: list[dict],
) -> list[VulnerabilityCreate]:
    """
    Normalize the combined raw output of all three scanners for a
    single scan into one flat list of VulnerabilityCreate objects,
    ready to be inserted via crud_vulnerability.create_vulnerability().
    """
    normalized: list[VulnerabilityCreate] = []

    for finding in semgrep_results:
        normalized.append(normalize_semgrep_finding(finding, scan_id))

    for finding in trivy_results:
        normalized.append(normalize_trivy_finding(finding, scan_id))

    for finding in trufflehog_results:
        normalized.append(normalize_trufflehog_finding(finding, scan_id))

    return normalized