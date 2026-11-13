
import pandas as pd

def detect_repeated_failed_logins(
    logs: pd.DataFrame,
    threshold: int = 5,
    window_minutes: int = 5,
    success_after_failure_threshold: int = 3,
) -> list[dict]:
    """Detect brute force and a successful login after repeated failures."""

    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")

    if success_after_failure_threshold < 1:
        raise ValueError("success_after_failure_threshold must be at least 1")

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

    alerts = []
    logins = events[events["event_type"] == "login"]
    window = pd.Timedelta(minutes=window_minutes)

    for source_ip, group in logins.groupby("source_ip"):
        group = group.sort_values("timestamp")
        failed_times = pd.DatetimeIndex(
            group.loc[group["status"] == "failed", "timestamp"]
        )
        successful_times = group.loc[
            group["status"] == "success", "timestamp"
        ]

        failed_group = group[group["status"] == "failed"].set_index("timestamp")
        counts = failed_group["status"].rolling(f"{window_minutes}min").count()
        failed_attempts = int(counts.max()) if not counts.empty else 0
        methods = []

        if failed_attempts >= threshold:
            methods.append("Repeated Failed Logins")

        success_after_failures = any(
            failed_times.searchsorted(success_time, side="left")
            - failed_times.searchsorted(success_time - window, side="right")
            >= success_after_failure_threshold
            for success_time in successful_times
        )
        if success_after_failures:
            methods.append("Successful Login After Repeated Failures")

        if methods:
            alerts.append({
                "source_ip": source_ip,
                "alert_type": (
                    "Successful Login After Repeated Failures"
                    if success_after_failures
                    else "Repeated Failed Logins"
                ),
                "severity": "High",
                "failed_attempts": failed_attempts,
                "window_minutes": window_minutes,
                "detection_methods": methods,
            })

    return alerts
