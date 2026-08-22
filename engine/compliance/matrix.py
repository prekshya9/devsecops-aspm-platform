from typing import List, Dict
from datetime import datetime
from ..parsers.models import UnifiedFinding, ScanReport, Severity


class ComplianceRiskEngine:
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 10.0,
        Severity.HIGH: 7.0,
        Severity.MEDIUM: 4.0,
        Severity.LOW: 1.0,
        Severity.INFO: 0.0
    }

    @classmethod
    def evaluate_scan(
        cls, 
        findings: List[UnifiedFinding], 
        repository: str = "main-service",
        commit_sha: str = "HEAD", 
        branch: str = "main"
    ) -> ScanReport:
        criticals = [f for f in findings if f.severity == Severity.CRITICAL]
        highs = [f for f in findings if f.severity == Severity.HIGH]
        mediums = [f for f in findings if f.severity == Severity.MEDIUM]
        lows = [f for f in findings if f.severity == Severity.LOW]

        # Security & Compliance Gate:
        # Fails/Blocks PR if ANY Critical exists or if more than 2 Highs exist
        is_compliant = (len(criticals) == 0 and len(highs) <= 2)

        return ScanReport(
            repository=repository,
            commit_sha=commit_sha,
            branch_or_pr=branch,
            timestamp=datetime.utcnow().isoformat() + "Z",
            total_findings=len(findings),
            critical_count=len(criticals),
            high_count=len(highs),
            medium_count=len(mediums),
            low_count=len(lows),
            findings=findings,
            is_compliant=is_compliant
        )

    @classmethod
    def generate_compliance_breakdown(cls, findings: List[UnifiedFinding]) -> Dict[str, int]:
        breakdown = {
            "GDPR_Article_25_Violations": 0,
            "GDPR_Article_32_Violations": 0,
            "ISO_27001_Controls_Failed": 0,
            "PCI_DSS_Non_Compliances": 0
        }

        for f in findings:
            if f.compliance:
                if f.compliance.gdpr_article and "Article 25" in f.compliance.gdpr_article:
                    breakdown["GDPR_Article_25_Violations"] += 1
                if f.compliance.gdpr_article and "Article 32" in f.compliance.gdpr_article:
                    breakdown["GDPR_Article_32_Violations"] += 1
                if f.compliance.iso_27001_control:
                    breakdown["ISO_27001_Controls_Failed"] += 1
                if f.compliance.pci_dss_requirement:
                    breakdown["PCI_DSS_Non_Compliances"] += 1

        return breakdown