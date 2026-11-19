from app.scanners.cloud_config import scan_cloud_resources


def test_detects_public_resource():
    resources = [
        {
            "resource_id": "bucket-001",
            "resource_type": "storage",
            "public_access": True,
            "encryption_enabled": True,
            "logging_enabled": True
        }
    ]

    result = scan_cloud_resources(resources)

    assert result["resources_scanned"] == 1
    assert result["total_findings"] == 1
    assert result["findings"][0]["severity"] == "HIGH"


def test_detects_disabled_encryption():
    resources = [
        {
            "resource_id": "database-001",
            "resource_type": "database",
            "public_access": False,
            "encryption_enabled": False,
            "logging_enabled": True
        }
    ]

    result = scan_cloud_resources(resources)

    assert result["total_findings"] == 1
    assert result["findings"][0]["issue"] == "Encryption is disabled"


def test_detects_disabled_logging():
    resources = [
        {
            "resource_id": "bucket-002",
            "resource_type": "storage",
            "public_access": False,
            "encryption_enabled": True,
            "logging_enabled": False
        }
    ]

    result = scan_cloud_resources(resources)

    assert result["total_findings"] == 1
    assert result["findings"][0]["issue"] == "Security logging is disabled"


def test_secure_resource_has_no_findings():
    resources = [
        {
            "resource_id": "bucket-003",
            "resource_type": "storage",
            "public_access": False,
            "encryption_enabled": True,
            "logging_enabled": True
        }
    ]

    result = scan_cloud_resources(resources)

    assert result["resources_scanned"] == 1
    assert result["total_findings"] == 0
