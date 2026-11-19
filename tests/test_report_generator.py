from app.reports.report_generator import generate_security_report


def test_generates_complete_security_report():
    cloud_scan = {"total_findings": 4}
    iam_analysis = {"total_findings": 3}
    attack_path_analysis = {"attack_paths_detected": 1}
    risk_analysis = {"total_findings": 4}
    recommendations = {"recommendations_generated": 3}

    result = generate_security_report(
        cloud_scan=cloud_scan,
        iam_analysis=iam_analysis,
        attack_path_analysis=attack_path_analysis,
        risk_analysis=risk_analysis,
        recommendations=recommendations
    )

    assert result["report_title"] == (
        "CloudGuard AI Security Assessment"
    )
    assert result["assessment_summary"]["cloud_findings"] == 4
    assert result["assessment_summary"]["iam_findings"] == 3
    assert result["assessment_summary"]["attack_paths_detected"] == 1
    assert result["assessment_summary"]["recommendations_generated"] == 3


def test_generates_report_with_empty_inputs():
    result = generate_security_report()

    assert result["assessment_summary"]["cloud_findings"] == 0
    assert result["assessment_summary"]["iam_findings"] == 0
    assert result["assessment_summary"]["attack_paths_detected"] == 0
    assert result["assessment_summary"]["recommendations_generated"] == 0


def test_report_contains_all_result_sections():
    result = generate_security_report()

    expected_sections = [
        "cloud_scan",
        "iam_analysis",
        "attack_path_analysis",
        "risk_analysis",
        "recommendations"
    ]

    for section in expected_sections:
        assert section in result["results"]


def test_report_has_generation_timestamp():
    result = generate_security_report()

    assert result["generated_at"]
    assert result["project"] == "CloudGuard AI"
