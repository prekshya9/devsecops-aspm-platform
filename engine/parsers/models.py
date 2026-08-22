from enum import Enum
from typing import Optional, List
from pydantic import BaseModel


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScannerType(str, Enum):
    SEMGREP = "SEMGREP"
    TRIVY_IAC = "TRIVY_IAC"
    TRIVY_VULN = "TRIVY_VULN"
    GITLEAKS = "GITLEAKS"


class ComplianceMapping(BaseModel):
    gdpr_article: Optional[str] = None
    iso_27001_control: Optional[str] = None
    pci_dss_requirement: Optional[str] = None


class UnifiedFinding(BaseModel):
    id: str
    scanner: ScannerType
    rule_id: str
    title: str
    description: str
    severity: Severity
    file_path: str
    start_line: int
    end_line: int
    code_snippet: Optional[str] = None
    remediation_advice: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    compliance: Optional[ComplianceMapping] = None
    introduced_in_pr: bool = True


class ScanReport(BaseModel):
    repository: str
    commit_sha: str
    branch_or_pr: str
    timestamp: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: List[UnifiedFinding] = []
    is_compliant: bool = True