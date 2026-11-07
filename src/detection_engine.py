from pathlib import Path

import pandas as pd

from .detection_rules import detect_repeated_failed_logins
from .predict import predict_activity
from .database import SessionLocal
from .database_service import (
    save_security_events,
    save_threat_alerts,
    get_latest_alert_created_at,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = PROJECT_ROOT / "data" / "sample_logs.csv"


def extract_ip_features(logs: pd.DataFrame) -> list[dict]:
    """Extract login activity features for each source IP."""

    required = {
        "timestamp",
        "username",
        "source_ip",
        "event_type",
        "status",
    }

    missing = required - set(logs.columns)

    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")

    events = logs.copy()
    events["timestamp"] = pd.to_datetime(events["timestamp"])

    features = []

    for source_ip, group in events.groupby("source_ip"):
        group = group.sort_values("timestamp")

        login_events = group[group["event_type"] == "login"]

        failed = login_events[login_events["status"] == "failed"]
        successful = login_events[login_events["status"] == "success"]

        failed_attempts = len(failed)
        unique_usernames = login_events["username"].nunique()

        if not login_events.empty:
            timed_events = login_events.set_index("timestamp")

            events_per_minute = int(
                timed_events["status"].rolling("1min").count().max()
            )
        else:
            events_per_minute = 0

        success_after_failures = int(
            not failed.empty
            and not successful.empty
            and successful["timestamp"].max()
            > failed["timestamp"].min()
        )

        features.append({
            "source_ip": source_ip,
            "failed_attempts": failed_attempts,
            "unique_usernames": unique_usernames,
            "events_per_minute": events_per_minute,
            "success_after_failures": success_after_failures,
        })

    return features


def run_detection():
    """Run rule-based and ML-based detection and save results."""

    logs = pd.read_csv(LOG_FILE)

    print(f"Total security events loaded: {len(logs)}")

    db = SessionLocal()

    try:
        # Save security events in PostgreSQL
        event_records = logs.to_dict(orient="records")

        saved_events = save_security_events(db, event_records)

        print(f"Security events saved: {saved_events}")

        # Rule-based detection
        rule_alerts = detect_repeated_failed_logins(logs)

        rule_alert_ips = {
            alert["source_ip"] for alert in rule_alerts
        }

        # Extract features for ML
        ip_features = extract_ip_features(logs)

        combined_alerts = []

        for features in ip_features:

            prediction = predict_activity(
                failed_attempts=features["failed_attempts"],
                unique_usernames=features["unique_usernames"],
                events_per_minute=features["events_per_minute"],
                success_after_failures=features[
                    "success_after_failures"
                ],
            )

            rule_triggered = (
                features["source_ip"] in rule_alert_ips
            )

            ml_triggered = (
                prediction["prediction"] == "Suspicious"
            )

            if rule_triggered or ml_triggered:

                reasons = []

                if rule_triggered:
                    reasons.append("Repeated failed login rule")

                if ml_triggered:
                    reasons.append(
                        "ML classified activity as suspicious"
                    )

                combined_alerts.append({
                    "source_ip": features["source_ip"],
                    "alert_type": "Suspicious Login Activity",
                    "severity": "High",
                    "description": "; ".join(reasons),
                    "detection_methods": reasons,
                    "failed_attempts": features["failed_attempts"],
                    "ml_prediction": prediction["prediction"],
                })

        # Save threat alerts in PostgreSQL
        if combined_alerts:
            saved_alerts = save_threat_alerts(
                db,
                combined_alerts,
            )

            print(f"Threat alerts saved: {saved_alerts}")

            # Retrieve the actual creation timestamp from PostgreSQL
            for alert in combined_alerts:
                alert["created_at"] = get_latest_alert_created_at(
                    db,
                    alert["source_ip"],
                )

        print("\nCombined Security Alerts")
        print("========================")

        if not combined_alerts:
            print("No suspicious activity detected.")
        else:
            for alert in combined_alerts:
                print(alert)

        return combined_alerts

    finally:
        db.close()


if __name__ == "__main__":
    run_detection()