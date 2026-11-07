import json
import re
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from .models import SecurityEvent, ThreatAlert


def save_security_events(db: Session, logs):
    """Save security events without inserting exact duplicates."""

    saved_count = 0

    for log in logs:
        timestamp = datetime.fromisoformat(str(log["timestamp"]))

        username = (
            str(log["username"])
            if log.get("username") is not None
            else None
        )

        source_ip = str(log["source_ip"])
        event_type = str(log["event_type"])
        status = str(log["status"])

        existing_event = db.query(SecurityEvent).filter(
            SecurityEvent.timestamp == timestamp,
            SecurityEvent.username == username,
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.event_type == event_type,
            SecurityEvent.status == status,
        ).first()

        if existing_event:
            continue

        record = SecurityEvent(
            timestamp=timestamp,
            username=username,
            source_ip=source_ip,
            event_type=event_type,
            status=status,
        )

        db.add(record)
        saved_count += 1

    db.commit()

    return saved_count


def save_threat_alerts(db: Session, alerts):
    """Save new alerts and update missing information in existing alerts."""

    saved_count = 0
    updated_count = 0

    cooldown_time = datetime.now() - timedelta(minutes=5)

    for alert in alerts:
        source_ip = str(alert["source_ip"])
        alert_type = "AI Cyber Threat Detection"
        severity = str(alert["severity"])

        detection_methods = alert.get("detection_methods", [])

        description = (
            "Detection methods: "
            + ", ".join(detection_methods)
            + f". Failed attempts: {alert.get('failed_attempts')}."
            + f" ML prediction: {alert.get('ml_prediction')}."
        )

        existing_alert = (
            db.query(ThreatAlert)
            .filter(
                ThreatAlert.source_ip == source_ip,
                ThreatAlert.alert_type == alert_type,
                ThreatAlert.severity == severity,
                ThreatAlert.created_at >= cooldown_time,
            )
            .order_by(ThreatAlert.created_at.desc())
            .first()
        )

        if existing_alert:
            if existing_alert.failed_attempts is None:
                existing_alert.failed_attempts = alert.get(
                    "failed_attempts"
                )

            if existing_alert.ml_prediction is None:
                existing_alert.ml_prediction = alert.get(
                    "ml_prediction"
                )

            if not existing_alert.detection_methods:
                existing_alert.detection_methods = json.dumps(
                    detection_methods
                )

            if not existing_alert.description:
                existing_alert.description = description

            updated_count += 1
            continue

        record = ThreatAlert(
            source_ip=source_ip,
            alert_type=alert_type,
            severity=severity,
            description=description,
            failed_attempts=alert.get("failed_attempts"),
            ml_prediction=alert.get("ml_prediction"),
            detection_methods=json.dumps(detection_methods),
        )

        db.add(record)
        saved_count += 1

    db.commit()

    print(f"New alerts saved: {saved_count}")
    print(f"Existing alerts updated: {updated_count}")

    return saved_count


def backfill_alert_details(db: Session):
    """
    Populate missing structured fields using existing alert descriptions.
    This preserves existing records and does not create duplicates.
    """

    updated_count = 0

    alerts = db.query(ThreatAlert).all()

    for alert in alerts:
        description = alert.description or ""

        # Extract failed login attempts.
        failed_match = re.search(
            r"Failed attempts:\s*(\d+)",
            description,
            re.IGNORECASE,
        )

        if alert.failed_attempts is None and failed_match:
            alert.failed_attempts = int(failed_match.group(1))

        # Extract ML prediction.
        prediction_match = re.search(
            r"ML prediction:\s*([^.]+)",
            description,
            re.IGNORECASE,
        )

        if alert.ml_prediction is None and prediction_match:
            alert.ml_prediction = prediction_match.group(1).strip()

        # Extract detection methods.
        methods_match = re.search(
            r"Detection methods:\s*(.*?)\.\s*Failed attempts:",
            description,
            re.IGNORECASE,
        )

        if not alert.detection_methods and methods_match:
            methods_text = methods_match.group(1).strip()

            methods = [
                method.strip()
                for method in methods_text.split(",")
                if method.strip()
            ]

            alert.detection_methods = json.dumps(methods)

        updated_count += 1

    db.commit()

    print(f"Alert records checked: {len(alerts)}")
    print(f"Alert records processed: {updated_count}")

    return updated_count


def get_latest_alert_created_at(db: Session, source_ip: str):
    """Retrieve the latest alert creation timestamp for an IP."""

    alert = (
        db.query(ThreatAlert)
        .filter(
            ThreatAlert.source_ip == source_ip,
            ThreatAlert.alert_type == "AI Cyber Threat Detection",
        )
        .order_by(
            ThreatAlert.created_at.desc(),
            ThreatAlert.id.desc(),
        )
        .first()
    )

    if alert and alert.created_at:
        return alert.created_at.isoformat()

    return None


def get_alert_history(db: Session, limit: int = 100):
    """Retrieve historical threat alerts from PostgreSQL."""

    alerts = (
        db.query(ThreatAlert)
        .order_by(
            ThreatAlert.created_at.desc(),
            ThreatAlert.id.desc(),
        )
        .limit(limit)
        .all()
    )

    history = []

    for alert in alerts:
        try:
            detection_methods = (
                json.loads(alert.detection_methods)
                if alert.detection_methods
                else []
            )

            if not isinstance(detection_methods, list):
                detection_methods = []

        except (json.JSONDecodeError, TypeError):
            detection_methods = []

        history.append({
            "id": alert.id,
            "source_ip": alert.source_ip,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "description": alert.description,
            "failed_attempts": alert.failed_attempts,
            "ml_prediction": alert.ml_prediction,
            "detection_methods": detection_methods,
            "created_at": (
                alert.created_at.isoformat()
                if alert.created_at
                else None
            ),
        })

    return history