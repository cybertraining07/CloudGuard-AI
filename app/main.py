
import json
from pathlib import Path
from fastapi.responses import FileResponse
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.scanners.cloud_config import scan_cloud_resources
from app.analyzers.iam_analyzer import analyze_iam_users
from app.analyzers.attack_path import analyze_attack_paths
from app.analyzers.risk_prioritizer import prioritize_risks
from app.analyzers.recommendation_engine import generate_recommendations
from app.reports.report_generator import generate_security_report
from app.reports.pdf_generator import generate_pdf_report


app = FastAPI(
    title="CloudGuard AI",
    description="Cloud Security Posture and Attack Path Analyzer",
    version="1.1.0"
)


# ==========================================
# REQUEST MODELS
# ==========================================

class CloudResource(BaseModel):
    resource_id: str
    resource_type: str
    public_access: bool
    encryption_enabled: bool
    logging_enabled: bool


class IAMUser(BaseModel):
    username: str
    admin_access: bool
    admin_required: bool
    mfa_enabled: bool
    days_since_last_login: int = Field(ge=0)


class AttackPathUser(BaseModel):
    username: str
    admin_access: bool
    mfa_enabled: bool
    accessible_resources: list[str]


class AttackPathResource(BaseModel):
    resource_id: str
    public_access: bool
    contains_sensitive_data: bool


class RiskFinding(BaseModel):
    severity: str
    issue: str
    description: str = ""
    resource_id: str = ""
    username: str = ""


class FullAssessmentRequest(BaseModel):
    cloud_resources: list[CloudResource]
    iam_users: list[IAMUser]
    attack_path_users: list[AttackPathUser]
    attack_path_resources: list[AttackPathResource]


# ==========================================
# HOME AND HEALTH
# ==========================================

@app.get("/")
def home():
    return {
        "project": "CloudGuard AI",
        "status": "running",
        "purpose": "Cloud security assessment"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "CloudGuard AI API"
    }


# ==========================================
# CLOUD CONFIGURATION SCANNER
# ==========================================

@app.post("/scan/config")
def scan_configuration(resources: list[CloudResource]):
    resource_data = [
        resource.model_dump()
        for resource in resources
    ]
    return scan_cloud_resources(resource_data)


# ==========================================
# IAM SECURITY ANALYZER
# ==========================================

@app.post("/analyze/iam")
def analyze_iam(users: list[IAMUser]):
    user_data = [
        user.model_dump()
        for user in users
    ]
    return analyze_iam_users(user_data)


# ==========================================
# ATTACK PATH ANALYZER
# ==========================================

@app.post("/analyze/attack-path")
def analyze_attack_path(
    users: list[AttackPathUser],
    resources: list[AttackPathResource]
):
    user_data = [
        user.model_dump()
        for user in users
    ]

    resource_data = [
        resource.model_dump()
        for resource in resources
    ]

    return analyze_attack_paths(
        user_data,
        resource_data
    )


# ==========================================
# RISK PRIORITIZATION ENGINE
# ==========================================

@app.post("/prioritize/risks")
def prioritize_security_risks(findings: list[RiskFinding]):
    finding_data = [
        finding.model_dump()
        for finding in findings
    ]
    return prioritize_risks(finding_data)


# ==========================================
# RECOMMENDATION ENGINE
# ==========================================

@app.post("/recommendations/generate")
def generate_security_recommendations(
    findings: list[RiskFinding]
):
    finding_data = [
        finding.model_dump()
        for finding in findings
    ]

    return generate_recommendations(finding_data)


# ==========================================
# SECURITY ASSESSMENT REPORT
# ==========================================

@app.post("/reports/generate")
def generate_report(
    cloud_scan: dict | None = None,
    iam_analysis: dict | None = None,
    attack_path_analysis: dict | None = None,
    risk_analysis: dict | None = None,
    recommendations: dict | None = None
):
    return generate_security_report(
        cloud_scan=cloud_scan,
        iam_analysis=iam_analysis,
        attack_path_analysis=attack_path_analysis,
        risk_analysis=risk_analysis,
        recommendations=recommendations
    )


# ==========================================
# COMPLETE CLOUD SECURITY ASSESSMENT
# ==========================================

@app.post("/assess/full")
def run_full_assessment(request: FullAssessmentRequest):

    # Convert validated input models into dictionaries
    cloud_data = [
        item.model_dump()
        for item in request.cloud_resources
    ]

    iam_data = [
        item.model_dump()
        for item in request.iam_users
    ]

    attack_users = [
        item.model_dump()
        for item in request.attack_path_users
    ]

    attack_resources = [
        item.model_dump()
        for item in request.attack_path_resources
    ]

    # Stage 1: Cloud configuration scanning
    cloud_scan = scan_cloud_resources(cloud_data)

    # Stage 2: IAM security analysis
    iam_analysis = analyze_iam_users(iam_data)

    # Stage 3: Attack path analysis
    attack_path_analysis = analyze_attack_paths(
        attack_users,
        attack_resources
    )

    # Stage 4: Combine findings for risk prioritization
    combined_findings = (
        cloud_scan.get("findings", [])
        + iam_analysis.get("findings", [])
        + attack_path_analysis.get("attack_paths", [])
    )

    risk_analysis = prioritize_risks(combined_findings)

    # Stage 5: Generate remediation recommendations
    recommendations = generate_recommendations(
        risk_analysis.get("findings", [])
    )

    # Generate and automatically save comprehensive report
    report = generate_security_report(
        cloud_scan=cloud_scan,
        iam_analysis=iam_analysis,
        attack_path_analysis=attack_path_analysis,
        risk_analysis=risk_analysis,
        recommendations=recommendations
    )

    return {
        "status": "completed",
        "assessment_engine": "CloudGuard AI Full Security Assessment",
        "assessment_results": report
    }

# ==========================================
# CLOUDGUARD AI SECURITY DASHBOARD
# ==========================================

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
DASHBOARD_FILE = BASE_DIR / "dashboard" / "index.html"


@app.get("/dashboard")
def security_dashboard():
    return FileResponse(DASHBOARD_FILE)


@app.get("/dashboard-data")
def dashboard_data():
    reports = sorted(
        REPORTS_DIR.glob("cloudguard_report_*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True
    )

    valid_reports = []

    for report_path in reports:
        try:
            with report_path.open("r", encoding="utf-8") as file:
                report = json.load(file)

            results = report.get("results", {})
            risk = results.get("risk_analysis", {})
            findings = risk.get("findings", [])

            valid_reports.append({
                "report_title": report.get("report_title", "Security Assessment"),
                "generated_at": report.get("generated_at", ""),
                "filename": report_path.name,
                "total_findings": len(findings)
            })

        except (json.JSONDecodeError, OSError):
            continue

    latest = None

    if valid_reports:
        latest_path = REPORTS_DIR / valid_reports[0]["filename"]

        with latest_path.open("r", encoding="utf-8") as file:
            latest = json.load(file)

    return {
        "status": "success",
        "total_reports": len(valid_reports),
        "latest": latest,
        "history": valid_reports[:10]
    }

# ==========================================
# PDF SECURITY REPORT DOWNLOAD
# ==========================================

@app.get("/reports/pdf/{filename}")
def download_pdf_report(filename: str):

    # Validate the requested report filename
    if (
        Path(filename).name != filename
        or not filename.startswith("cloudguard_report_")
        or not filename.endswith(".json")
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid report filename"
        )

    source_path = REPORTS_DIR / filename

    if not source_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Report not found"
        )

    try:
        pdf_path = Path(generate_pdf_report(source_path))

    except (json.JSONDecodeError, OSError, ValueError) as exc:
        raise HTTPException(
            status_code=500,
            detail="Could not generate PDF report"
        ) from exc

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=pdf_path.name
    )
