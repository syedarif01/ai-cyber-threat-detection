
import pandas as pd

def detect_repeated_failed_logins(
    logs: pd.DataFrame,
    threshold: int = 5,
    window_minutes: int = 5,
) -> list[dict]:
    """Detect repeated failed logins from a source IP."""

    required = {
        "timestamp",
        "source_ip",
        "event_type",
        "status",
    }

    missing = required - set(logs.columns)
    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")

    events = logs.copy()
    events["timestamp"] = pd.to_datetime(
        events["timestamp"], errors="raise"
    )

    failed = events[
        (events["event_type"] == "login")
        & (events["status"] == "failed")
    ].sort_values("timestamp")

    alerts = []

    for source_ip, group in failed.groupby("source_ip"):
        group = group.set_index("timestamp").sort_index()

        counts = group["status"].rolling(
            f"{window_minutes}min"
        ).count()

        if (counts >= threshold).any():
            alerts.append({
                "source_ip": source_ip,
                "alert_type": "Repeated Failed Logins",
                "severity": "High",
                "failed_attempts": int(counts.max()),
                "window_minutes": window_minutes,
            })

    return alerts