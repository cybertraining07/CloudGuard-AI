
def scan_cloud_resources(resources):
    findings = []

    for resource in resources:

        resource_id = resource["resource_id"]
        resource_type = resource["resource_type"]

        # Check public exposure
        if resource["public_access"]:
            findings.append({
                "resource_id": resource_id,
                "resource_type": resource_type,
                "severity": "HIGH",
                "issue": "Publicly accessible resource",
                "description": (
                    "The resource allows public access."
                ),
                "recommendation": (
                    "Restrict public access and review "
                    "the resource's access policies."
                )
            })

        # Check encryption
        if not resource["encryption_enabled"]:
            findings.append({
                "resource_id": resource_id,
                "resource_type": resource_type,
                "severity": "MEDIUM",
                "issue": "Encryption is disabled",
                "description": (
                    "The resource does not have "
                    "encryption enabled."
                ),
                "recommendation": (
                    "Enable appropriate encryption "
                    "for stored data."
                )
            })

        # Check security logging
        if not resource["logging_enabled"]:
            findings.append({
                "resource_id": resource_id,
                "resource_type": resource_type,
                "severity": "MEDIUM",
                "issue": "Security logging is disabled",
                "description": (
                    "Logging is not enabled for this resource."
                ),
                "recommendation": (
                    "Enable appropriate logging and "
                    "monitor security events."
                )
            })

    return {
        "scanner": "CloudGuard AI",
        "resources_scanned": len(resources),
        "total_findings": len(findings),
        "findings": findings
    }
