
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

def test_missing_columns_raise_error():
    logs = pd.DataFrame({"username": ["arif"]})

    with pytest.raises(ValueError):
        detect_repeated_failed_logins(logs)