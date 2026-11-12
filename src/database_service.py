import json
import re

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from .models import SecurityEvent, ThreatAlert


# --------------------------------------------------
# INCIDENT CORRELATION CONFIGURATION
# --------------------------------------------------

CORRELATION_WINDOW_MINUTES = 30

ACTIVE_STATUSES = [
    "New",
    "Acknowledged",
    "Investigating",
]

ALERT_TYPE = "AI Cyber Threat Detection"

SEVERITY_PRIORITY = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}


# --------------------------------------------------
# AUTOMATIC SEVERITY ESCALATION CONFIGURATION
# --------------------------------------------------

OCCURRENCE_SEVERITY_THRESHOLDS = {
    3: "Medium",
    5: "High",
    10: "Critical",
}

FAILED_ATTEMPT_SEVERITY_THRESHOLDS = {
    5: "High",
    10: "Critical",
}


# --------------------------------------------------
# CALCULATE AUTOMATIC INCIDENT SEVERITY
# --------------------------------------------------

def calculate_incident_severity(
    current_severity,
    occurrence_count,
    failed_attempts
):
    """
    Automatically calculate incident severity.

    Escalation is based on:
    - Total occurrence count
    - Failed login attempts

    Existing severity is never downgraded.
    """

    current_priority = SEVERITY_PRIORITY.get(
        current_severity,
        0
    )

    calculated_severity = current_severity

    calculated_priority = current_priority

    # ----------------------------------------------
    # CHECK OCCURRENCE COUNT
    # ----------------------------------------------

    for threshold, severity in sorted(
        OCCURRENCE_SEVERITY_THRESHOLDS.items()
    ):

        if occurrence_count >= threshold:

            priority = SEVERITY_PRIORITY[severity]

            if priority > calculated_priority:

                calculated_severity = severity

                calculated_priority = priority

    # ----------------------------------------------
    # CHECK FAILED LOGIN ATTEMPTS
    # ----------------------------------------------

    for threshold, severity in sorted(
        FAILED_ATTEMPT_SEVERITY_THRESHOLDS.items()
    ):

        if failed_attempts >= threshold:

            priority = SEVERITY_PRIORITY[severity]

            if priority > calculated_priority:

                calculated_severity = severity

                calculated_priority = priority

    return calculated_severity


# --------------------------------------------------
# SAVE SECURITY EVENTS
# --------------------------------------------------

def save_security_events(db: Session, logs):

    """
    Save only genuinely new security events.

    Exact duplicate events are ignored.

    Newly inserted event counts are stored in
    db.info for incident correlation.
    """

    saved_count = 0

    new_event_counts = {}

    processed_events = set()

    for log in logs:

        timestamp = datetime.fromisoformat(
            str(log["timestamp"])
        )

        username = (
            str(log["username"])
            if log.get("username") is not None
            else None
        )

        source_ip = str(log["source_ip"])

        event_type = str(log["event_type"])

        status = str(log["status"])

        # Create unique event fingerprint.

        event_fingerprint = (
            timestamp,
            username,
            source_ip,
            event_type,
            status,
        )

        # Prevent duplicates within same batch.

        if event_fingerprint in processed_events:

            continue

        processed_events.add(event_fingerprint)

        # Check whether event already exists.

        existing_event = (
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.timestamp == timestamp,
                SecurityEvent.username == username,
                SecurityEvent.source_ip == source_ip,
                SecurityEvent.event_type == event_type,
                SecurityEvent.status == status,
            )
            .first()
        )

        if existing_event:

            continue

        # Insert genuinely new security event.

        record = SecurityEvent(
            timestamp=timestamp,
            username=username,
            source_ip=source_ip,
            event_type=event_type,
            status=status,
        )

        db.add(record)

        saved_count += 1

        new_event_counts[source_ip] = (
            new_event_counts.get(source_ip, 0) + 1
        )

    db.commit()

    # Store new event counts for incident processing.

    db.info["new_security_event_counts"] = (
        new_event_counts
    )

    duplicate_count = (
        len(processed_events) - saved_count
    )

    print(
        f"New security events inserted: {saved_count}"
    )

    print(
        f"Duplicate security events ignored: {duplicate_count}"
    )

    return saved_count


# --------------------------------------------------
# SAVE OR CORRELATE THREAT INCIDENTS
# --------------------------------------------------

def save_threat_alerts(db: Session, alerts):

    """
    Create new incidents or update existing incidents.

    An incident is updated only when genuinely new
    security events have been inserted.

    Correlation criteria:

    - Source IP
    - Alert type
    - Active incident status
    - 30-minute correlation window

    Automatic severity escalation:

    - Based on occurrence count
    - Based on failed login attempts
    - Existing severity is never downgraded
    """

    saved_count = 0

    correlated_count = 0

    skipped_count = 0

    escalated_count = 0

    current_time = datetime.now()

    correlation_cutoff = (
        current_time
        - timedelta(minutes=CORRELATION_WINDOW_MINUTES)
    )

    # Retrieve newly inserted event counts.

    new_event_counts = db.info.pop(
        "new_security_event_counts",
        {}
    )

    # Avoid processing same IP more than once.

    processed_source_ips = set()

    for alert in alerts:

        source_ip = str(alert["source_ip"])

        if source_ip in processed_source_ips:

            continue

        processed_source_ips.add(source_ip)

        # Get genuinely new events for this IP.

        new_event_count = new_event_counts.get(
            source_ip,
            0
        )

        # No new events means no new occurrence.

        if new_event_count <= 0:

            skipped_count += 1

            print(
                f"Skipped repeated detection for {source_ip}"
            )

            continue

        severity = str(alert["severity"])

        detection_methods = alert.get(
            "detection_methods",
            []
        )

        if not isinstance(detection_methods, list):

            detection_methods = []

        detection_methods = [
            str(method)
            for method in detection_methods
        ]

        failed_attempts = (
            alert.get("failed_attempts") or 0
        )

        description = (
            "Detection methods: "
            + ", ".join(detection_methods)
            + f". Failed attempts: {failed_attempts}."
            + f" ML prediction: {alert.get('ml_prediction')}."
        )

        # ------------------------------------------
        # FIND EXISTING ACTIVE INCIDENT
        # ------------------------------------------

        existing_alert = (
            db.query(ThreatAlert)
            .filter(
                ThreatAlert.source_ip == source_ip,
                ThreatAlert.alert_type == ALERT_TYPE,
                ThreatAlert.status.in_(ACTIVE_STATUSES),
                ThreatAlert.created_at >= correlation_cutoff,
            )
            .order_by(
                ThreatAlert.created_at.desc(),
                ThreatAlert.id.desc(),
            )
            .first()
        )

        # ------------------------------------------
        # UPDATE EXISTING INCIDENT
        # ------------------------------------------

        if existing_alert:

            old_severity = existing_alert.severity

            # Increase occurrence count.

            existing_alert.occurrence_count = (
                (existing_alert.occurrence_count or 1)
                + new_event_count
            )

            # Update last-seen timestamp.

            existing_alert.last_seen_at = current_time

            # --------------------------------------
            # UPDATE FAILED ATTEMPTS
            # --------------------------------------

            existing_alert.failed_attempts = max(
                existing_alert.failed_attempts or 0,
                failed_attempts,
            )

            # --------------------------------------
            # AUTOMATIC SEVERITY ESCALATION
            # --------------------------------------

            new_severity = calculate_incident_severity(
                current_severity=existing_alert.severity,
                occurrence_count=existing_alert.occurrence_count,
                failed_attempts=existing_alert.failed_attempts,
            )

            existing_alert.severity = new_severity

            if new_severity != old_severity:

                escalated_count += 1

                print(
                    f"SEVERITY ESCALATED: {source_ip} "
                    f"{old_severity} -> {new_severity}"
                )

            # --------------------------------------
            # UPDATE LATEST ML PREDICTION
            # --------------------------------------

            existing_alert.ml_prediction = alert.get(
                "ml_prediction"
            )

            # --------------------------------------
            # MERGE DETECTION METHODS
            # --------------------------------------

            try:

                old_methods = (
                    json.loads(existing_alert.detection_methods)
                    if existing_alert.detection_methods
                    else []
                )

                if not isinstance(old_methods, list):

                    old_methods = []

            except (json.JSONDecodeError, TypeError):

                old_methods = []

            merged_methods = list(
                dict.fromkeys(
                    old_methods + detection_methods
                )
            )

            existing_alert.detection_methods = json.dumps(
                merged_methods
            )

            # --------------------------------------
            # UPDATE DESCRIPTION
            # --------------------------------------

            existing_alert.description = description

            # Preserve existing:
            #
            # - Incident status
            # - Analyst notes
            # - Acknowledged timestamp
            # - Resolved timestamp
            # - Original creation timestamp

            correlated_count += 1

            continue

        # ------------------------------------------
        # CREATE NEW INCIDENT
        # ------------------------------------------

        initial_occurrence_count = new_event_count

        # Calculate initial severity for new incident.

        initial_severity = calculate_incident_severity(
            current_severity=severity,
            occurrence_count=initial_occurrence_count,
            failed_attempts=failed_attempts,
        )

        if initial_severity != severity:

            escalated_count += 1

            print(
                f"INITIAL SEVERITY ESCALATED: "
                f"{source_ip} {severity} -> {initial_severity}"
            )

        record = ThreatAlert(
            source_ip=source_ip,

            alert_type=ALERT_TYPE,

            severity=initial_severity,

            description=description,

            failed_attempts=failed_attempts,

            ml_prediction=alert.get(
                "ml_prediction"
            ),

            detection_methods=json.dumps(
                detection_methods
            ),

            occurrence_count=initial_occurrence_count,

            last_seen_at=current_time,

            status="New",
        )

        db.add(record)

        saved_count += 1

    db.commit()

    # ----------------------------------------------
    # INCIDENT PROCESSING SUMMARY
    # ----------------------------------------------

    print("----------------------------------")

    print("INCIDENT PROCESSING SUMMARY")

    print("----------------------------------")

    print(
        f"New incidents created: {saved_count}"
    )

    print(
        f"Existing incidents correlated: {correlated_count}"
    )

    print(
        f"Repeated detections skipped: {skipped_count}"
    )

    print(
        f"Incidents escalated: {escalated_count}"
    )

    print("----------------------------------")

    return saved_count


# --------------------------------------------------
# BACKFILL EXISTING ALERT DETAILS
# --------------------------------------------------

def backfill_alert_details(db: Session):

    """
    Populate missing structured fields using
    existing alert descriptions.

    Existing records are preserved.
    """

    updated_count = 0

    alerts = db.query(ThreatAlert).all()

    for alert in alerts:

        changed = False

        description = alert.description or ""

        # ------------------------------------------
        # EXTRACT FAILED ATTEMPTS
        # ------------------------------------------

        failed_match = re.search(
            r"Failed attempts:\s*(\d+)",
            description,
            re.IGNORECASE,
        )

        if alert.failed_attempts is None and failed_match:

            alert.failed_attempts = int(
                failed_match.group(1)
            )

            changed = True

        # ------------------------------------------
        # EXTRACT ML PREDICTION
        # ------------------------------------------

        prediction_match = re.search(
            r"ML prediction:\s*([^.]+)",
            description,
            re.IGNORECASE,
        )

        if alert.ml_prediction is None and prediction_match:

            alert.ml_prediction = (
                prediction_match.group(1).strip()
            )

            changed = True

        # ------------------------------------------
        # EXTRACT DETECTION METHODS
        # ------------------------------------------

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

            alert.detection_methods = json.dumps(
                methods
            )

            changed = True

        if changed:

            updated_count += 1

    db.commit()

    print(
        f"Alert records checked: {len(alerts)}"
    )

    print(
        f"Alert records updated: {updated_count}"
    )

    return updated_count


# --------------------------------------------------
# GET LATEST ALERT CREATION TIMESTAMP
# --------------------------------------------------

def get_latest_alert_created_at(
    db: Session,
    source_ip: str
):

    """
    Retrieve the latest incident creation timestamp
    for a particular source IP.
    """

    alert = (
        db.query(ThreatAlert)
        .filter(
            ThreatAlert.source_ip == source_ip,
            ThreatAlert.alert_type == ALERT_TYPE,
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


# --------------------------------------------------
# GET ALERT HISTORY
# --------------------------------------------------

def get_alert_history(
    db: Session,
    limit: int = 100
):

    """
    Retrieve historical threat incidents
    from PostgreSQL.
    """

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

        # Safely decode detection methods.

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

            "occurrence_count": alert.occurrence_count,

            "last_seen_at": (
                alert.last_seen_at.isoformat()
                if alert.last_seen_at
                else None
            ),

            "status": alert.status,

            "analyst_notes": alert.analyst_notes,

            "acknowledged_at": (
                alert.acknowledged_at.isoformat()
                if alert.acknowledged_at
                else None
            ),

            "resolved_at": (
                alert.resolved_at.isoformat()
                if alert.resolved_at
                else None
            ),

            "created_at": (
                alert.created_at.isoformat()
                if alert.created_at
                else None
            ),

        })

    return history