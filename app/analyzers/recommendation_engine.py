
def generate_recommendations(findings):
    recommendations = []

    remediation_rules = {
        "publicly accessible resource": {
            "action": (
                "Restrict public access and review resource access policies."
            ),
            "reason": (
                "Public exposure may allow unauthorized parties "
                "to access cloud resources."
            ),
            "verification": (
                "Confirm public access is disabled and only "
                "authorized identities can access the resource."
            )
        },
        "encryption is disabled": {
            "action": (
                "Enable encryption at rest using an appropriate encryption key."
            ),
            "reason": (
                "Unencrypted stored data may be exposed if "
                "unauthorized access occurs."
            ),
            "verification": (
                "Confirm encryption is enabled and key policies "
                "are properly configured."
            )
        },
        "security logging is disabled": {
            "action": (
                "Enable security logging and configure centralized log collection."
            ),
            "reason": (
                "Missing logs can prevent timely detection and "
                "investigation of suspicious activity."
            ),
            "verification": (
                "Generate a test event and confirm that it appears "
                "in the security logging system."
            )
        },
        "excessive administrator privileges": {
            "action": (
                "Remove unnecessary administrator permissions "
                "and apply least privilege."
            ),
            "reason": (
                "Excessive permissions increase the potential "
                "impact of compromised identities."
            ),
            "verification": (
                "Review effective permissions and confirm the "
                "identity only has required access."
            )
        },
        "multi-factor authentication disabled": {
            "action": "Enable MFA for the affected identity.",
            "reason": (
                "Without MFA, stolen credentials may be easier to misuse."
            ),
            "verification": (
                "Confirm MFA is enabled and successfully required "
                "during authentication."
            )
        },
        "inactive user account": {
            "action": (
                "Review the account and disable it if it is no longer required."
            ),
            "reason": (
                "Unused accounts can create unnecessary opportunities "
                "for unauthorized access."
            ),
            "verification": (
                "Confirm account ownership and business need, "
                "then verify its status."
            )
        },
        "critical attack path": {
            "action": (
                "Immediately review the identity's effective permissions, "
                "remove unnecessary administrator access, enforce MFA, "
                "and restrict access to the sensitive resource. "
                "Remove public exposure where applicable."
            ),
            "reason": (
                "The detected path combines privileged identity access "
                "and exposure of a sensitive resource, potentially "
                "increasing the impact of identity compromise."
            ),
            "verification": (
                "Verify effective identity permissions, confirm MFA "
                "enforcement, inspect resource access policies, and "
                "confirm that public access is disabled where required. "
                "Rerun the assessment to check whether the path remains."
            )
        }
    }

    for finding in findings:

        # Detect attack-path findings using their structure
        is_attack_path = (
            "attack_path" in finding
            or (
                "identity" in finding
                and "target_resource" in finding
            )
        )

        if is_attack_path:
            issue = "Critical attack path"

            rule = remediation_rules["critical attack path"]

            username = finding.get("identity", "")
            resource_id = finding.get("target_resource", "")

        else:
            issue = finding.get("issue", "")
            normalized_issue = issue.lower()

            rule = remediation_rules.get(normalized_issue)

            username = finding.get("username", "")
            resource_id = finding.get("resource_id", "")

        # Fallback for unrecognized findings
        if rule is None:
            rule = {
                "action": (
                    "Investigate the finding and apply an appropriate "
                    "security control."
                ),
                "reason": (
                    "The finding requires additional security review."
                ),
                "verification": (
                    "Repeat the relevant security assessment and "
                    "confirm the issue is resolved."
                )
            }

        recommendations.append({
            "issue": issue,
            "severity": finding.get("severity", "UNKNOWN"),
            "resource_id": resource_id,
            "username": username,
            "recommended_action": rule["action"],
            "risk_explanation": rule["reason"],
            "verification_steps": rule["verification"]
        })

    return {
        "engine": "CloudGuard AI Recommendation Engine",
        "findings_reviewed": len(findings),
        "recommendations_generated": len(recommendations),
        "recommendations": recommendations
    }
