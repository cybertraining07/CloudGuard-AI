from app.analyzers.recommendation_engine import generate_recommendations


def test_recommends_public_access_restriction():
    findings = [
        {
            "severity": "HIGH",
            "issue": "Publicly accessible resource",
            "resource_id": "bucket-001"
        }
    ]

    result = generate_recommendations(findings)

    assert result["recommendations_generated"] == 1
    assert "Restrict public access" in (
        result["recommendations"][0]["recommended_action"]
    )


def test_recommends_encryption():
    findings = [
        {
            "severity": "MEDIUM",
            "issue": "Encryption is disabled",
            "resource_id": "database-001"
        }
    ]

    result = generate_recommendations(findings)

    assert result["recommendations_generated"] == 1
    assert "encryption" in (
        result["recommendations"][0]["recommended_action"].lower()
    )


def test_recommends_mfa():
    findings = [
        {
            "severity": "HIGH",
            "issue": "Multi-factor authentication disabled",
            "username": "test_user"
        }
    ]

    result = generate_recommendations(findings)

    assert result["recommendations_generated"] == 1
    assert "MFA" in (
        result["recommendations"][0]["recommended_action"]
    )


def test_empty_findings():
    result = generate_recommendations([])

    assert result["findings_reviewed"] == 0
    assert result["recommendations_generated"] == 0
    assert result["recommendations"] == []
