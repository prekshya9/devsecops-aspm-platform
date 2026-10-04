import os
import sys
from typing import List
from github import Github

# Import our engine components
from engine.parsers.models import ScanReport, UnifiedFinding, Severity
from engine.parsers.semgrep_parser import parse_semgrep_json
from engine.parsers.infrastructure_parser import parse_trivy_iac_json, parse_gitleaks_json
from engine.compliance.matrix import ComplianceRiskEngine


def read_file_safe(path: str) -> str:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return ""


def generate_pr_markdown_summary(report: ScanReport, breakdown: dict) -> str:
    status_badge = "🚨 **MERGE BLOCKED (Non-Compliant)**" if not report.is_compliant else "✅ **SECURITY & COMPLIANCE GATE PASSED**"
    
    body = f"""## 🛡️ ASPM DevSecOps Security & Compliance Audit

### Status: {status_badge}

| Metric | Count |
| :--- | :--- |
| **Total Security Findings** | `{report.total_findings}` |
| **Critical Severity** | `{report.critical_count}` |
| **High Severity** | `{report.high_count}` |
| **Medium Severity** | `{report.medium_count}` |
| **Low Severity** | `{report.low_count}` |

---

### 📋 Governance & Regulatory Compliance Breakdown
* **GDPR Article 32 (Security of Processing):** `{breakdown.get('GDPR_Article_32_Violations', 0)}` violations
* **GDPR Article 25 (Privacy by Design):** `{breakdown.get('GDPR_Article_25_Violations', 0)}` violations
* **ISO 27001 Control Failures:** `{breakdown.get('ISO_27001_Controls_Failed', 0)}` non-compliances
* **PCI-DSS Violations:** `{breakdown.get('PCI_DSS_Non_Compliances', 0)}` issues

---

### 🔍 Key Findings Breakdown
"""

    if not report.findings:
        body += "\n*No vulnerabilities or compliance violations detected.*\n"
        return body

    for idx, f in enumerate(report.findings[:10], start=1):
        gdpr_note = f.compliance.gdpr_article if f.compliance and f.compliance.gdpr_article else "N/A"
        iso_note = f.compliance.iso_27001_control if f.compliance and f.compliance.iso_27001_control else "N/A"
        
        body += f"""
#### {idx}. [{f.severity.value}] {f.title} (`{f.scanner.value}`)
* **File Location:** `{f.file_path}:{f.start_line}`
* **Description:** {f.description}
* **GDPR Mapping:** {gdpr_note}
* **ISO 27001 Control:** {iso_note}
* **Remediation Advice:** {f.remediation_advice}
"""
    return body


def run_bot():
    token = os.getenv("GITHUB_TOKEN")
    repo_name = os.getenv("GITHUB_REPOSITORY")
    pr_number = os.getenv("PR_NUMBER")

    # Load raw scan JSON files from artifacts
    semgrep_raw = read_file_safe("semgrep-report.json")
    trivy_raw = read_file_safe("trivy-iac-report.json")
    gitleaks_raw = read_file_safe("gitleaks-report.json")

    # Parse and normalize findings
    all_findings: List[UnifiedFinding] = []
    if semgrep_raw:
        all_findings.extend(parse_semgrep_json(semgrep_raw))
    if trivy_raw:
        all_findings.extend(parse_trivy_iac_json(trivy_raw))
    if gitleaks_raw:
        all_findings.extend(parse_gitleaks_json(gitleaks_raw))

    # Evaluate compliance and policy gates
    report = ComplianceRiskEngine.evaluate_scan(
        findings=all_findings,
        repository=repo_name or "local-repo",
    )
    breakdown = ComplianceRiskEngine.generate_compliance_breakdown(all_findings)
    markdown_comment = generate_pr_markdown_summary(report, breakdown)

    # Print summary to console output
    print(markdown_comment)

    # Post comment to GitHub PR if running in GitHub Actions environment
    if token and repo_name and pr_number:
        try:
            gh = Github(token)
            repo = gh.get_repo(repo_name)
            pull_request = repo.get_pull(int(pr_number))
            pull_request.create_issue_comment(markdown_comment)
            print("Successfully posted security audit comment to PR.")
        except Exception as e:
            print(f"Error posting comment to GitHub API: {e}")

    # Enforce merge-block exit code
    if not report.is_compliant:
        print("CI Gate Failed: Security vulnerabilities exceed threshold.")
        sys.exit(1)


if __name__ == "__main__":
    run_bot()