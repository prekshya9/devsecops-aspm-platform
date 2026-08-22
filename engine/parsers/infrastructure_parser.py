import json
from typing import List
from .models import UnifiedFinding, Severity, ScannerType, ComplianceMapping


def map_trivy_severity(raw: str) -> Severity:
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    return mapping.get(raw.upper(), Severity.LOW)


def parse_trivy_iac_json(raw_json_str: str) -> List[UnifiedFinding]:
    """Parses Trivy Infrastructure-as-Code (Terraform) scan reports."""
    findings: List[UnifiedFinding] = []
    if not raw_json_str.strip():
        return findings

    data = json.loads(raw_json_str)
    results = data.get("Results", [])

    for res in results:
        target = res.get("Target", "")
        misconfigs = res.get("Misconfigurations", [])

        for mis in misconfigs:
            rule_id = mis.get("ID", "UNKNOWN_IAC")
            title = mis.get("Title", "Cloud Misconfiguration")
            desc = mis.get("Description", "")
            resolution = mis.get("Resolution", "Remediate Terraform configuration.")
            raw_sev = mis.get("Severity", "MEDIUM")
            lines = mis.get("IacMetadata", {}).get("StartLine", 1)

            compliance = ComplianceMapping(
                gdpr_article="Article 32 (Technical & Organizational Security Measures)",
                iso_27001_control="A.8.20 (Network Security) & A.8.9 (Configuration Management)",
                pci_dss_requirement="Req 1.3 & Req 2.2 (Secure System Configuration)"
            )

            finding = UnifiedFinding(
                id=f"TRIVY-IAC-{rule_id}-{target}-{lines}",
                scanner=ScannerType.TRIVY_IAC,
                rule_id=rule_id,
                title=title,
                description=desc,
                severity=map_trivy_severity(raw_sev),
                file_path=target,
                start_line=lines,
                end_line=lines,
                remediation_advice=resolution,
                compliance=compliance
            )
            findings.append(finding)

    return findings


def parse_gitleaks_json(raw_json_str: str) -> List[UnifiedFinding]:
    """Parses Gitleaks raw JSON for hardcoded secrets and leaked tokens."""
    findings: List[UnifiedFinding] = []
    if not raw_json_str.strip():
        return findings

    items = json.loads(raw_json_str)
    if not isinstance(items, list):
        return findings

    for item in items:
        rule_id = item.get("RuleID", "generic-secret")
        file_path = item.get("File", "")
        start = item.get("StartLine", 1)
        end = item.get("EndLine", 1)
        secret_masked = item.get("Secret", "")[:4] + "****"

        compliance = ComplianceMapping(
            gdpr_article="Article 32 (Security of Processing - Unauthorized Access)",
            iso_27001_control="A.5.15 (Access Control & Credential Management)",
            pci_dss_requirement="Req 8.2 (User Authentication & Key Management)"
        )

        finding = UnifiedFinding(
            id=f"GITLEAKS-{rule_id}-{file_path}-{start}",
            scanner=ScannerType.GITLEAKS,
            rule_id=rule_id,
            title=f"Hardcoded Secret ({rule_id})",
            description=f"Exposed secret detected in source code: {secret_masked}",
            severity=Severity.CRITICAL,
            file_path=file_path,
            start_line=start,
            end_line=end,
            remediation_advice="Revoke and rotate the exposed secret immediately. Store in a secure vault.",
            compliance=compliance
        )
        findings.append(finding)

    return findings