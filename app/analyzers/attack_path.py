
def analyze_attack_paths(users, resources):
    attack_paths = []

    for user in users:
        for resource in resources:

            # Require an explicit identity-to-resource relationship.
            # Administrator status alone does not prove resource access.
            accessible_resources = user.get(
                "accessible_resources", []
            )

            has_access = (
                resource["resource_id"] in accessible_resources
            )

            # Identify risky access to sensitive resources.
            if has_access and resource["contains_sensitive_data"]:

                risk_factors = []

                if user["admin_access"]:
                    risk_factors.append(
                        "Identity has administrator privileges"
                    )

                if not user["mfa_enabled"]:
                    risk_factors.append(
                        "Multi-factor authentication is disabled"
                    )

                if resource["public_access"]:
                    risk_factors.append(
                        "Resource is publicly accessible"
                    )

                severity = (
                    "CRITICAL"
                    if user["admin_access"]
                    and resource["public_access"]
                    else "HIGH"
                )

                attack_paths.append({
                    "identity": user["username"],
                    "target_resource": resource["resource_id"],
                    "severity": severity,
                    "attack_path": [
                        user["username"],
                        resource["resource_id"],
                        "Sensitive data"
                    ],
                    "risk_factors": risk_factors,
                    "recommendation": (
                        "Apply least privilege, review resource "
                        "access policies, restrict public exposure "
                        "and enable MFA."
                    )
                })

    return {
        "analyzer": "CloudGuard AI Attack Path Analyzer",
        "identities_analyzed": len(users),
        "resources_analyzed": len(resources),
        "attack_paths_detected": len(attack_paths),
        "attack_paths": attack_paths
    }
