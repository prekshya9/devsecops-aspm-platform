import sqlite3
import json
from fastapi import FastAPI, HTTPException
from typing import List, Dict
from engine.parsers.models import ScanReport, UnifiedFinding
from engine.compliance.matrix import ComplianceRiskEngine

app = FastAPI(
    title="Enterprise ASPM & GDPR Compliance API",
    description="Central Security Posture Management API for tracking vulnerability posture and GDPR/ISO 27001 governance.",
    version="1.0.0"
)

DB_PATH = "security_posture.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repository TEXT,
            commit_sha TEXT,
            branch_or_pr TEXT,
            timestamp TEXT,
            total_findings INTEGER,
            critical_count INTEGER,
            high_count INTEGER,
            medium_count INTEGER,
            low_count INTEGER,
            is_compliant INTEGER,
            raw_findings TEXT
        )
    """)
    conn.commit()
    conn.close()


init_db()


@app.get("/")
def root():
    return {
        "status": "online",
        "service": "DevSecOps ASPM Compliance Service",
        "supported_standards": ["GDPR Art 25/32", "ISO 27001", "PCI-DSS"]
    }


@app.post("/api/v1/scans", status_code=201)
def ingest_scan_report(report: ScanReport):
    """Ingests a completed scan report from any CI/CD pipeline run."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    findings_json = json.dumps([f.model_dump() for f in report.findings])

    cursor.execute("""
        INSERT INTO scan_reports (
            repository, commit_sha, branch_or_pr, timestamp,
            total_findings, critical_count, high_count, medium_count, low_count,
            is_compliant, raw_findings
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        report.repository,
        report.commit_sha,
        report.branch_or_pr,
        report.timestamp,
        report.total_findings,
        report.critical_count,
        report.high_count,
        report.medium_count,
        report.low_count,
        1 if report.is_compliant else 0,
        findings_json
    ))
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()

    return {"message": "Scan report ingested successfully", "scan_id": scan_id}


@app.get("/api/v1/compliance/summary")
def get_compliance_executive_summary():
    """Returns real-time compliance metrics for GRC and Data Protection officers."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT raw_findings FROM scan_reports")
    rows = cursor.fetchall()
    conn.close()

    all_findings: List[UnifiedFinding] = []
    for (findings_raw,) in rows:
        if findings_raw:
            data = json.loads(findings_raw)
            for item in data:
                all_findings.append(UnifiedFinding(**item))

    breakdown = ComplianceRiskEngine.generate_compliance_breakdown(all_findings)
    total_scanned = len(rows)

    return {
        "total_repositories_scanned": total_scanned,
        "total_active_violations": len(all_findings),
        "governance_metrics": breakdown,
        "audit_readiness_score": f"{max(0, 100 - (len(all_findings) * 5))}%"
    }


@app.get("/api/v1/scans/history")
def list_scans_history():
    """Returns historical scan audit trail."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, repository, commit_sha, branch_or_pr, timestamp,
               total_findings, critical_count, high_count, is_compliant
        FROM scan_reports ORDER BY id DESC LIMIT 50
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]