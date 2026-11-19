from app.analyzers.risk_prioritizer import prioritize_risks


def test_critical_risk_gets_highest_score():
    findings = [
        {
            "severity": "CRITICAL",
            "issue": "Critical cloud exposure"
        }
    ]

    result = prioritize_risks(findings)

    assert result["findings"][0]["risk_score"] == 100
    assert result["findings"][0]["priority"] == "IMMEDIATE"


def test_high_risk_priority():
    findings = [
        {
            "severity": "HIGH",
            "issue": "Public storage"
        }
    ]

    result = prioritize_risks(findings)

    assert result["findings"][0]["risk_score"] == 75
    assert result["findings"][0]["priority"] == "URGENT"


def test_findings_sorted_by_risk_score():
    findings = [
        {"severity": "LOW", "issue": "Low risk"},
        {"severity": "CRITICAL", "issue": "Critical risk"},
        {"severity": "MEDIUM", "issue": "Medium risk"}
    ]

    result = prioritize_risks(findings)

    scores = [
        finding["risk_score"]
        for finding in result["findings"]
    ]

    assert scores == [100, 50, 25]


def test_empty_findings():
    result = prioritize_risks([])

    assert result["total_findings"] == 0
    assert result["findings"] == []
