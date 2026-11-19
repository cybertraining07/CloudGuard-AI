def analyze_iam_users(users):
    findings = []

    for user in users:

        username = user["username"]

        if user["admin_access"] and not user["admin_required"]:
            findings.append({
                "username": username,
                "severity": "HIGH",
                "issue": "Excessive administrator privileges",
                "recommendation": (
                    "Apply least privilege and remove "
                    "unnecessary administrator access."
                )
            })

        if not user["mfa_enabled"]:
            findings.append({
                "username": username,
                "severity": "HIGH",
                "issue": "Multi-factor authentication disabled",
                "recommendation": (
                    "Enable MFA for this identity."
                )
            })

        if user["days_since_last_login"] >= 90:
            findings.append({
                "username": username,
                "severity": "MEDIUM",
                "issue": "Inactive user account",
                "recommendation": (
                    "Review the account and disable it "
                    "if it is no longer required."
                )
            })

    return {
        "analyzer": "CloudGuard AI IAM Analyzer",
        "users_analyzed": len(users),
        "total_findings": len(findings),
        "findings": findings
    }
