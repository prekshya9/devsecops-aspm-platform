import json
from typing import List
from .models import UnifiedFinding, Severity, ScannerType, ComplianceMapping


def map_semgrep_severity(raw_severity: str) -> Severity:
    raw = raw_severity.upper()
    if raw == "ERROR":
        return Severity.HIGH
    elif raw == "WARNING":
        return Severity.MEDIUM
    elif raw == "INFO":
        return Severity.LOW
    return Severity.MEDIUM


def extract_compliance_metadata(metadata: dict) -> ComplianceMapping:
    cwe = str(metadata.get("cwe", ""))
    gdpr = None
    iso = "A.8.28 (Secure Coding)"

    # Check for PII / Logging violations (GDPR Art. 32)
    if "CWE-532" in cwe or "GDPR" in str(metadata.get("compliance", "")):
        gdpr = "Article 32 (Security of Processing - PII Protection)"
    # Check for SQL / Injection flaws (GDPR Art. 25 & PCI-DSS)
    elif "CWE-89" in cwe:
        gdpr = "Article 25 (Privacy by Design - Data Integrity)"
        iso = "A.8.24 (Input Validation & Cryptography)"

    return ComplianceMapping(
        gdpr_article=gdpr,
        iso_27001_control=iso,
        pci_dss_requirement="Req 6.5" if "CWE-89" in cwe else None
    )


def parse_semgrep_json(raw_json_str: str) -> List[UnifiedFinding]:
    """Parses raw Semgrep JSON results into our unified data model."""
    if not raw_json_str.strip():
        return []

    data = json.loads(raw_json_str)
    results = data.get("results", [])
    findings: List[UnifiedFinding] = []

    for item in results:
        check_id = item.get("check_id", "unknown-rule")
        path = item.get("path", "")
        start = item.get("start", {}).get("line", 1)
        end = item.get("end", {}).get("line", 1)
        extra = item.get("extra", {})
        message = extra.get("message", "No description provided.")
        raw_sev = extra.get("severity", "WARNING")
        metadata = extra.get("metadata", {})
        snippet = extra.get("lines", "")

        finding = UnifiedFinding(
            id=f"SEMGREP-{check_id}-{path}-{start}",
            scanner=ScannerType.SEMGREP,
            rule_id=check_id,
            title=check_id.split(".")[-1],
            description=message,
            severity=map_semgrep_severity(raw_sev),
            file_path=path,
            start_line=start,
            end_line=end,
            code_snippet=snippet,
            cwe_id=str(metadata.get("cwe", "Unknown")),
            compliance=extract_compliance_metadata(metadata),
            remediation_advice="Review line and apply data masking or input validation."
        )
        findings.append(finding)

    return findings