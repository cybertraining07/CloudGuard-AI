from app.analyzers.iam_analyzer import analyze_iam_users


def test_detects_excessive_admin_privileges():
    users = [
        {
            "username": "admin_test",
            "admin_access": True,
            "admin_required": False,
            "mfa_enabled": True,
            "days_since_last_login": 10
        }
    ]

    result = analyze_iam_users(users)

    assert result["total_findings"] == 1
    assert result["findings"][0]["issue"] == (
        "Excessive administrator privileges"
    )


def test_detects_disabled_mfa():
    users = [
        {
            "username": "user_test",
            "admin_access": False,
            "admin_required": False,
            "mfa_enabled": False,
            "days_since_last_login": 10
        }
    ]

    result = analyze_iam_users(users)

    assert result["total_findings"] == 1
    assert result["findings"][0]["issue"] == (
        "Multi-factor authentication disabled"
    )


def test_detects_inactive_account():
    users = [
        {
            "username": "inactive_user",
            "admin_access": False,
            "admin_required": False,
            "mfa_enabled": True,
            "days_since_last_login": 120
        }
    ]

    result = analyze_iam_users(users)

    assert result["total_findings"] == 1
    assert result["findings"][0]["issue"] == "Inactive user account"


def test_secure_active_user_has_no_findings():
    users = [
        {
            "username": "secure_user",
            "admin_access": False,
            "admin_required": False,
            "mfa_enabled": True,
            "days_since_last_login": 20
        }
    ]

    result = analyze_iam_users(users)

    assert result["total_findings"] == 0
