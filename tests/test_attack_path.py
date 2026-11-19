
from app.analyzers.attack_path import analyze_attack_paths


def test_detects_critical_attack_path():
    users = [
        {
            "username": "admin_test",
            "admin_access": True,
            "mfa_enabled": False,
            "accessible_resources": ["sensitive-bucket"]
        }
    ]

    resources = [
        {
            "resource_id": "sensitive-bucket",
            "public_access": True,
            "contains_sensitive_data": True
        }
    ]

    result = analyze_attack_paths(users, resources)

    assert result["attack_paths_detected"] == 1
    assert result["attack_paths"][0]["identity"] == "admin_test"
    assert result["attack_paths"][0]["target_resource"] == "sensitive-bucket"
    assert result["attack_paths"][0]["severity"] == "CRITICAL"


def test_detects_high_risk_attack_path():
    users = [
        {
            "username": "regular_user",
            "admin_access": False,
            "mfa_enabled": False,
            "accessible_resources": ["sensitive-database"]
        }
    ]

    resources = [
        {
            "resource_id": "sensitive-database",
            "public_access": False,
            "contains_sensitive_data": True
        }
    ]

    result = analyze_attack_paths(users, resources)

    assert result["attack_paths_detected"] == 1
    assert result["attack_paths"][0]["severity"] == "HIGH"
    assert result["attack_paths"][0]["identity"] == "regular_user"


def test_no_path_to_non_sensitive_resource():
    users = [
        {
            "username": "regular_user",
            "admin_access": False,
            "mfa_enabled": True,
            "accessible_resources": ["public-bucket"]
        }
    ]

    resources = [
        {
            "resource_id": "public-bucket",
            "public_access": False,
            "contains_sensitive_data": False
        }
    ]

    result = analyze_attack_paths(users, resources)

    assert result["attack_paths_detected"] == 0
    assert result["attack_paths"] == []


def test_no_path_without_access():
    users = [
        {
            "username": "regular_user",
            "admin_access": False,
            "mfa_enabled": True,
            "accessible_resources": []
        }
    ]

    resources = [
        {
            "resource_id": "sensitive-bucket",
            "public_access": False,
            "contains_sensitive_data": True
        }
    ]

    result = analyze_attack_paths(users, resources)

    assert result["attack_paths_detected"] == 0
    assert result["attack_paths"] == []


def test_admin_without_explicit_access_has_no_attack_path():
    users = [
        {
            "username": "admin_test",
            "admin_access": True,
            "mfa_enabled": False,
            "accessible_resources": []
        }
    ]

    resources = [
        {
            "resource_id": "sensitive-bucket",
            "public_access": True,
            "contains_sensitive_data": True
        }
    ]

    result = analyze_attack_paths(users, resources)

    assert result["attack_paths_detected"] == 0
    assert result["attack_paths"] == []
