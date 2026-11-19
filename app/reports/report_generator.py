
import json
from datetime import datetime, timezone
from pathlib import Path


def generate_security_report(
    cloud_scan=None,
    iam_analysis=None,
    attack_path_analysis=None,
    risk_analysis=None,
    recommendations=None
):
    generated_at = datetime.now(timezone.utc)

    timestamp = generated_at.strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    report = {
        "report_title": "CloudGuard AI Security Assessment",
        "generated_at": generated_at.isoformat(),
        "project": "CloudGuard AI",
        "assessment_summary": {
            "cloud_findings": (
                cloud_scan.get("total_findings", 0)
                if cloud_scan else 0
            ),
            "iam_findings": (
                iam_analysis.get("total_findings", 0)
                if iam_analysis else 0
            ),
            "attack_paths_detected": (
                attack_path_analysis.get("attack_paths_detected", 0)
                if attack_path_analysis else 0
            ),
            "prioritized_findings": (
                risk_analysis.get("total_findings", 0)
                if risk_analysis else 0
            ),
            "recommendations_generated": (
                recommendations.get("recommendations_generated", 0)
                if recommendations else 0
            )
        },
        "results": {
            "cloud_scan": cloud_scan or {},
            "iam_analysis": iam_analysis or {},
            "attack_path_analysis": attack_path_analysis or {},
            "risk_analysis": risk_analysis or {},
            "recommendations": recommendations or {}
        }
    }

    # Create the reports directory
    project_root = Path(__file__).resolve().parents[2]
    reports_directory = project_root / "reports"
    reports_directory.mkdir(parents=True, exist_ok=True)

    # Generate a unique report filename
    filename = f"cloudguard_report_{timestamp}.json"
    report_path = reports_directory / filename

    # Include the relative report path in the report
    report["report_file"] = f"reports/{filename}"

    # Save the report as formatted JSON
    with report_path.open("w", encoding="utf-8") as report_file:
        json.dump(
            report,
            report_file,
            indent=4,
            ensure_ascii=False
        )

    return report
