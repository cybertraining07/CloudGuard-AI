
def prioritize_risks(findings):
    severity_scores = {
        "CRITICAL": 100,
        "HIGH": 75,
        "MEDIUM": 50,
        "LOW": 25
    }

    prioritized = []

    for finding in findings:
        severity = finding["severity"].upper()

        score = severity_scores.get(severity, 0)

        prioritized.append({
            **finding,
            "risk_score": score,
            "priority": (
                "IMMEDIATE"
                if score >= 100
                else "URGENT"
                if score >= 75
                else "MODERATE"
                if score >= 50
                else "LOW"
            )
        })

    prioritized.sort(
        key=lambda item: item["risk_score"],
        reverse=True
    )

    return {
        "engine": "CloudGuard AI Risk Prioritization Engine",
        "total_findings": len(prioritized),
        "findings": prioritized
    }
