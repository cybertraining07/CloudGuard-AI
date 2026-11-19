
from app import main
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_home_endpoint():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["project"] == "CloudGuard AI"


def test_cloud_scan_endpoint():
    payload = [
        {
            "resource_id": "bucket-test-001",
            "resource_type": "storage",
            "public_access": True,
            "encryption_enabled": True,
            "logging_enabled": True
        }
    ]

    response = client.post("/scan/config", json=payload)

    assert response.status_code == 200
    assert response.json()["resources_scanned"] == 1
    assert response.json()["total_findings"] == 1


def test_iam_endpoint():
    payload = [
        {
            "username": "test_admin",
            "admin_access": True,
            "admin_required": False,
            "mfa_enabled": False,
            "days_since_last_login": 120
        }
    ]

    response = client.post("/analyze/iam", json=payload)

    assert response.status_code == 200
    assert response.json()["users_analyzed"] == 1


def test_full_assessment_endpoint():
    payload = {
        "cloud_resources": [
            {
                "resource_id": "sensitive-storage-001",
                "resource_type": "storage",
                "public_access": True,
                "encryption_enabled": False,
                "logging_enabled": False
            },
            {
                "resource_id": "database-001",
                "resource_type": "database",
                "public_access": False,
                "encryption_enabled": False,
                "logging_enabled": True
            }
        ],
        "iam_users": [
            {
                "username": "john_admin",
                "admin_access": True,
                "admin_required": False,
                "mfa_enabled": False,
                "days_since_last_login": 120
            },
            {
                "username": "mary_user",
                "admin_access": False,
                "admin_required": False,
                "mfa_enabled": True,
                "days_since_last_login": 10
            }
        ],
        "attack_path_users": [
            {
                "username": "john_admin",
                "admin_access": True,
                "mfa_enabled": False,
                "accessible_resources": [
                    "sensitive-storage-001"
                ]
            }
        ],
        "attack_path_resources": [
            {
                "resource_id": "sensitive-storage-001",
                "public_access": True,
                "contains_sensitive_data": True
            }
        ]
    }

    response = client.post("/assess/full", json=payload)

    assert response.status_code == 200

    result = response.json()

    assert result["status"] == "completed"
    assert (
        result["assessment_engine"]
        == "CloudGuard AI Full Security Assessment"
    )

    assessment = result["assessment_results"]

    # Verify assessment summary
    summary = assessment["assessment_summary"]

    assert summary["cloud_findings"] == 4
    assert summary["iam_findings"] == 3
    assert summary["attack_paths_detected"] == 1
    assert summary["prioritized_findings"] == 8
    assert summary["recommendations_generated"] == 8

    # Verify cloud scan
    cloud_scan = assessment["results"]["cloud_scan"]

    assert cloud_scan["resources_scanned"] == 2
    assert cloud_scan["total_findings"] == 4

    # Verify IAM analysis
    iam_analysis = assessment["results"]["iam_analysis"]

    assert iam_analysis["users_analyzed"] == 2
    assert iam_analysis["total_findings"] == 3

    # Verify attack path analysis
    attack_paths = assessment["results"]["attack_path_analysis"]

    assert attack_paths["attack_paths_detected"] == 1

    detected_path = attack_paths["attack_paths"][0]

    assert detected_path["identity"] == "john_admin"
    assert detected_path["target_resource"] == "sensitive-storage-001"
    assert detected_path["severity"] == "CRITICAL"

    # Verify risk prioritization
    risk_analysis = assessment["results"]["risk_analysis"]

    assert risk_analysis["total_findings"] == 8

    # Verify recommendations
    recommendations = assessment["results"]["recommendations"]

    assert recommendations["recommendations_generated"] == 8

    # Verify report file information
    assert assessment["report_title"] == (
        "CloudGuard AI Security Assessment"
    )

    assert assessment["project"] == "CloudGuard AI"
    assert assessment["report_file"].startswith(
        "reports/cloudguard_report_"
    )
    assert assessment["report_file"].endswith(".json")


def test_dashboard_endpoint():
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "CloudGuard AI" in response.text


def test_dashboard_data_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "REPORTS_DIR", tmp_path)

    report_path = tmp_path / "cloudguard_report_test.json"

    report_path.write_text(
        '{"report_title":"Test Assessment",'
        '"generated_at":"2026-01-01T00:00:00+00:00",'
        '"results":{"risk_analysis":{"findings":['
        '{"severity":"HIGH"},{"severity":"MEDIUM"}]}}}',
        encoding="utf-8"
    )

    response = client.get("/dashboard-data")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "success"
    assert data["total_reports"] == 1
    assert data["latest"]["report_title"] == "Test Assessment"
    assert data["history"][0]["filename"] == "cloudguard_report_test.json"
    assert data["history"][0]["total_findings"] == 2


def test_pdf_report_download_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "REPORTS_DIR", tmp_path)

    report_path = tmp_path / "cloudguard_report_pdf_test.json"
    report_path.write_text(
        '{"report_title":"Test Assessment",'
        '"project":"CloudGuard AI",'
        '"generated_at":"2026-01-01T00:00:00+00:00",'
        '"assessment_summary":{},'
        '"results":{'
        '"risk_analysis":{"findings":[]},'
        '"cloud_scan":{"findings":[]},'
        '"iam_analysis":{"findings":[]},'
        '"attack_path_analysis":{"attack_paths":[]},'
        '"recommendations":{"recommendations":[]}'
        '}}',
        encoding="utf-8"
    )

    response = client.get(
        "/reports/pdf/cloudguard_report_pdf_test.json"
    )

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF")
