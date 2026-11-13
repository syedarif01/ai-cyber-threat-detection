
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "src")
)

from detection_rules import detect_repeated_failed_logins

def make_logs(statuses):
    return pd.DataFrame([
        {
            "timestamp": f"2026-10-15 09:02:{i * 10:02d}",
            "username": "arif",
            "source_ip": "192.0.2.50",
            "event_type": "login",
            "status": status,
        }
        for i, status in enumerate(statuses)
    ])

def test_detects_five_failed_logins():
    logs = make_logs(["failed"] * 5)

    alerts = detect_repeated_failed_logins(logs)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "High"
    assert alerts[0]["failed_attempts"] == 5

def test_no_alert_for_four_failed_logins():
    logs = make_logs(["failed"] * 4)

    alerts = detect_repeated_failed_logins(logs)

    assert alerts == []

def test_successful_logins_do_not_trigger_alert():
    logs = make_logs(["success"] * 6)

    alerts = detect_repeated_failed_logins(logs)

    assert alerts == []

def test_success_after_three_recent_failures_triggers_credential_rule():
    logs = make_logs(["failed", "failed", "failed", "success"])

    alerts = detect_repeated_failed_logins(logs)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "Successful Login After Repeated Failures"
    assert alerts[0]["detection_methods"] == [
        "Successful Login After Repeated Failures"
    ]

def test_success_after_fewer_than_three_failures_does_not_trigger():
    logs = make_logs(["failed", "failed", "success"])

    assert detect_repeated_failed_logins(logs) == []

def test_success_after_failures_outside_window_does_not_trigger():
    logs = make_logs(["failed", "failed", "failed", "success"])
    logs["timestamp"] = [
        "2026-10-15 09:00:00",
        "2026-10-15 09:00:10",
        "2026-10-15 09:00:20",
        "2026-10-15 09:06:00",
    ]

    assert detect_repeated_failed_logins(logs) == []

def test_threshold_must_be_positive_for_success_rule():
    logs = make_logs(["failed", "success"])

    with pytest.raises(ValueError, match="success_after_failure_threshold"):
        detect_repeated_failed_logins(logs, success_after_failure_threshold=0)

def test_failed_logins_across_multiple_accounts_trigger_rule():
    logs = make_logs(["failed"] * 6)
    logs["username"] = [f"account-{i}" for i in range(6)]

    alerts = detect_repeated_failed_logins(logs)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "192.0.2.50"
    assert alerts[0]["failed_attempts"] == 6

def test_benign_mixed_logins_below_threshold_do_not_trigger_alert():
    logs = make_logs(["failed", "success", "failed", "success"])

    assert detect_repeated_failed_logins(logs) == []

def test_missing_columns_raise_error():
    logs = pd.DataFrame({"username": ["arif"]})

    with pytest.raises(ValueError):
        detect_repeated_failed_logins(logs)

def test_attempts_outside_the_window_do_not_trigger_alert():
    logs = make_logs(["failed"] * 5)
    logs["timestamp"] = [
        f"2026-10-15 09:{minute:02d}:00"
        for minute in (0, 2, 4, 6, 8)
    ]

    assert detect_repeated_failed_logins(logs, window_minutes=5) == []

def test_threshold_and_window_must_be_positive():
    logs = make_logs(["failed"] * 5)

    with pytest.raises(ValueError, match="threshold"):
        detect_repeated_failed_logins(logs, threshold=0)

    with pytest.raises(ValueError, match="window_minutes"):
        detect_repeated_failed_logins(logs, window_minutes=0)
