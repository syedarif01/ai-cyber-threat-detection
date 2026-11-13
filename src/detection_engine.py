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
LAST_DETECTION_WARNINGS = []


def get_last_detection_warnings() -> list[str]:
    """Return runtime limitations from the most recent detection run."""
    return list(LAST_DETECTION_WARNINGS)


# --------------------------------------------------
# EXTRACT IP FEATURES
# --------------------------------------------------

def extract_ip_features(logs: pd.DataFrame) -> list[dict]:
    """
    Extract login activity features for each source IP.
    """

    required = {
        "timestamp",
        "username",
        "source_ip",
        "event_type",
        "status",
    }

    missing = required - set(logs.columns)

    if missing:
        raise ValueError(
            f"Missing columns: {sorted(missing)}"
        )

    events = logs.copy()

    events["timestamp"] = pd.to_datetime(
        events["timestamp"]
    )

    features = []

    for source_ip, group in events.groupby("source_ip"):

        group = group.sort_values("timestamp")

        login_events = group[
            group["event_type"] == "login"
        ]

        failed = login_events[
            login_events["status"] == "failed"
        ]

        successful = login_events[
            login_events["status"] == "success"
        ]

        failed_attempts = len(failed)

        unique_usernames = login_events[
            "username"
        ].nunique()

        if not login_events.empty:

            timed_events = login_events.set_index(
                "timestamp"
            )

            events_per_minute = int(
                timed_events["status"]
                .rolling("1min")
                .count()
                .max()
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

            "success_after_failures": (
                success_after_failures
            ),

        })

    return features


# --------------------------------------------------
# MAIN DETECTION ENGINE
# --------------------------------------------------

def run_detection():
    """
    Run rule-based and ML-based threat detection.

    Processing sequence:

    1. Load security logs.
    2. Insert only new security events.
    3. Perform rule-based detection.
    4. Extract IP features.
    5. Perform ML prediction.
    6. Combine suspicious detections.
    7. Create or correlate incidents.

    All database operations use the same session.
    """

    global LAST_DETECTION_WARNINGS
    LAST_DETECTION_WARNINGS = []

    if not LOG_FILE.exists():

        raise FileNotFoundError(
            f"Security log file not found: {LOG_FILE}"
        )

    logs = pd.read_csv(LOG_FILE)

    print("\n==================================")
    print("CYBERGUARD AI DETECTION ENGINE")
    print("==================================")

    print(
        f"Total security events loaded: {len(logs)}"
    )

    db = SessionLocal()

    try:

        # ------------------------------------------
        # STEP 1: SAVE SECURITY EVENTS
        # ------------------------------------------

        print("\n[1] Processing security events...")

        event_records = logs.to_dict(
            orient="records"
        )

        saved_events = save_security_events(
            db,
            event_records,
        )

        print(
            f"New security events saved: {saved_events}"
        )

        if saved_events == 0:

            print(
                "No new security events found. "
                "Previously processed events will "
                "not increase incident counts."
            )

        # ------------------------------------------
        # STEP 2: RULE-BASED DETECTION
        # ------------------------------------------

        print("\n[2] Running rule-based detection...")

        rule_alerts = detect_repeated_failed_logins(
            logs
        )

        rule_alerts_by_ip = {
            alert["source_ip"]: alert
            for alert in rule_alerts
        }

        print(
            f"Rule-based alerts detected: "
            f"{len(rule_alerts)}"
        )

        # ------------------------------------------
        # STEP 3: EXTRACT IP FEATURES
        # ------------------------------------------

        print("\n[3] Extracting IP features...")

        ip_features = extract_ip_features(
            logs
        )

        print(
            f"Unique IP addresses processed: "
            f"{len(ip_features)}"
        )

        combined_alerts = []

        # ------------------------------------------
        # STEP 4: MACHINE LEARNING DETECTION
        # ------------------------------------------

        print("\n[4] Running machine learning detection...")

        for features in ip_features:

            prediction = predict_activity(

                failed_attempts=features[
                    "failed_attempts"
                ],

                unique_usernames=features[
                    "unique_usernames"
                ],

                events_per_minute=features[
                    "events_per_minute"
                ],

                success_after_failures=features[
                    "success_after_failures"
                ],

            )

            if prediction.get("model_available") is False:
                warning = (
                    "ML classifier unavailable; this run used rule-based "
                    "detections only."
                )
                if warning not in LAST_DETECTION_WARNINGS:
                    LAST_DETECTION_WARNINGS.append(warning)

            rule_triggered = (
                features["source_ip"]
                in rule_alerts_by_ip
            )

            ml_triggered = (
                prediction["prediction"]
                == "Suspicious"
            )

            # --------------------------------------
            # STEP 5: COMBINE DETECTION RESULTS
            # --------------------------------------

            if rule_triggered or ml_triggered:

                reasons = []

                if rule_triggered:
                    reasons.extend(
                        rule_alerts_by_ip[features["source_ip"]].get(
                            "detection_methods",
                            ["Repeated Failed Logins"],
                        )
                    )

                if ml_triggered:

                    reasons.append(
                        "ML classified activity as suspicious"
                    )

                combined_alerts.append({

                    "source_ip": features["source_ip"],

                    "alert_type": (
                        "Suspicious Login Activity"
                    ),

                    "severity": "High",

                    "description": "; ".join(reasons),

                    "detection_methods": reasons,

                    "failed_attempts": features[
                        "failed_attempts"
                    ],

                    "ml_prediction": prediction[
                        "prediction"
                    ],

                })

        # ------------------------------------------
        # STEP 6: SAVE OR CORRELATE INCIDENTS
        # ------------------------------------------

        print("\n[5] Processing threat incidents...")

        if combined_alerts:

            new_incidents = save_threat_alerts(
                db,
                combined_alerts,
            )

            print(
                f"New incidents created: {new_incidents}"
            )

            # Retrieve database creation timestamps.
            for alert in combined_alerts:

                alert["created_at"] = (
                    get_latest_alert_created_at(
                        db,
                        alert["source_ip"],
                    )
                )

        else:

            print(
                "No suspicious activity detected."
            )

        # ------------------------------------------
        # STEP 7: DISPLAY SECURITY ALERTS
        # ------------------------------------------

        print("\n==================================")

        print("COMBINED SECURITY ALERTS")

        print("==================================")

        if not combined_alerts:

            print(
                "No suspicious activity detected."
            )

        else:

            for alert in combined_alerts:

                print("\n------------------------------")

                print(
                    f"Source IP: {alert['source_ip']}"
                )

                print(
                    f"Severity: {alert['severity']}"
                )

                print(
                    f"Failed Attempts: "
                    f"{alert['failed_attempts']}"
                )

                print(
                    f"ML Prediction: "
                    f"{alert['ml_prediction']}"
                )

                print(
                    f"Detection Methods: "
                    f"{alert['detection_methods']}"
                )

                print(
                    f"Created At: "
                    f"{alert.get('created_at')}"
                )

        print("\n==================================")
        print("DETECTION COMPLETED")
        print("==================================")

        return combined_alerts

    finally:

        db.close()


# --------------------------------------------------
# APPLICATION ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":

    run_detection()
