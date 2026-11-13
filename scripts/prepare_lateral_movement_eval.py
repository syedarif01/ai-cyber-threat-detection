"""Prepare the public synthetic auth benchmark for a time-separated evaluation.

Source: https://www.kaggle.com/datasets/codewithdaniel1/synthetic-enterprise-auth-logs
The generated labels describe synthetic lateral movement, not production attacks.
"""

import argparse
from collections import Counter, deque
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FEATURES = [
    "failed_attempts",
    "unique_usernames",
    "events_per_minute",
    "success_after_failures",
]
REQUIRED_COLUMNS = {
    "event_id",
    "timestamp",
    "user_id",
    "src_host",
    "auth_result",
    "is_malicious",
}


def prepare(input_path: Path, train_output: Path, test_output: Path) -> tuple[int, int]:
    events = pd.read_csv(input_path)
    missing = sorted(REQUIRED_COLUMNS - set(events.columns))
    if missing:
        raise ValueError(f"Missing benchmark columns: {', '.join(missing)}")
    if events[["event_id", "timestamp", "src_host", "auth_result", "is_malicious"]].isna().any().any():
        raise ValueError("Benchmark has missing event, time, host, status, or label values.")

    labels = pd.to_numeric(events["is_malicious"], errors="raise")
    if not set(labels.unique()).issubset({0, 1}):
        raise ValueError("is_malicious must contain only 0 (benign) and 1 (malicious).")
    events["label"] = labels.astype(int)
    events["timestamp"] = pd.to_datetime(events["timestamp"], errors="coerce", utc=True)
    if events["timestamp"].isna().any():
        raise ValueError("Benchmark has invalid timestamps.")

    events["_auth_result"] = events["auth_result"].astype(str).str.strip().str.lower()
    if not set(events["_auth_result"].unique()).issubset({"success", "failure"}):
        raise ValueError("auth_result must contain only Success or Failure values.")
    events["_user_id"] = events["user_id"].fillna("__unknown_user__").astype(str)
    events["_row"] = range(len(events))
    events = events.sort_values(
        ["src_host", "timestamp", "event_id"], kind="stable"
    )

    # For each event, use authentication context available in the preceding
    # minute plus the current event. The current event's malicious label is
    # copied only as the target and is never used as a feature.
    feature_rows: list[list[int] | None] = [None] * len(events)
    columns = ["timestamp", "_user_id", "_auth_result", "_row"]
    for _, host_events in events.groupby("src_host", sort=False):
        active: deque[tuple[pd.Timestamp, str, bool]] = deque()
        user_counts: Counter[str] = Counter()
        failed_count = 0
        for timestamp, user_id, result, row_index in host_events[columns].itertuples(
            index=False, name=None
        ):
            cutoff = timestamp - pd.Timedelta(minutes=1)
            while active and active[0][0] <= cutoff:
                _, expired_user, expired_failure = active.popleft()
                user_counts[expired_user] -= 1
                if user_counts[expired_user] == 0:
                    del user_counts[expired_user]
                failed_count -= int(expired_failure)

            failures_before_current = failed_count
            is_failure = result == "failure"
            active.append((timestamp, user_id, is_failure))
            user_counts[user_id] += 1
            failed_count += int(is_failure)
            feature_rows[row_index] = [
                failed_count,
                len(user_counts),
                len(active),
                int(result == "success" and failures_before_current > 0),
            ]

    features = pd.DataFrame(feature_rows, columns=FEATURES)
    features["label"] = events.sort_values("_row", kind="stable")["label"].to_numpy()
    times = events.sort_values("_row", kind="stable")["timestamp"].reset_index(drop=True)

    # The source describes May 1–7 as baseline, May 8–15 as model-fit, and
    # May 16–30 as held-out evaluation. Exclude baseline rows from this RF run.
    fit_start = pd.Timestamp("2026-05-08", tz="UTC")
    test_start = pd.Timestamp("2026-05-16", tz="UTC")
    end_exclusive = pd.Timestamp("2026-05-31", tz="UTC")
    train_mask = (times >= fit_start) & (times < test_start)
    test_mask = (times >= test_start) & (times < end_exclusive)
    train_data = features.loc[train_mask].reset_index(drop=True)
    test_data = features.loc[test_mask].reset_index(drop=True)

    for split_name, split in [("model-fit", train_data), ("held-out", test_data)]:
        if len(split) < 40 or split["label"].nunique() != 2:
            raise ValueError(
                f"{split_name} split must have at least 40 rows and both labels; "
                f"found {len(split)} rows and labels {sorted(split['label'].unique())}."
            )

    train_output.parent.mkdir(parents=True, exist_ok=True)
    test_output.parent.mkdir(parents=True, exist_ok=True)
    train_data.to_csv(train_output, index=False)
    test_data.to_csv(test_output, index=False)
    return len(train_data), len(test_data)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Downloaded benchmark CSV")
    parser.add_argument(
        "--train-output",
        type=Path,
        default=PROJECT_ROOT / "data" / "phase3_train.csv",
    )
    parser.add_argument(
        "--test-output",
        type=Path,
        default=PROJECT_ROOT / "data" / "phase3_test.csv",
    )
    args = parser.parse_args()
    try:
        train_rows, test_rows = prepare(args.input, args.train_output, args.test_output)
    except (OSError, ValueError, pd.errors.ParserError) as error:
        parser.error(str(error))
    print(f"Model-fit rows: {train_rows}; held-out rows: {test_rows}")
    print(f"Training features: {args.train_output}")
    print(f"Held-out features: {args.test_output}")
    print("Labels represent synthetic lateral movement; do not interpret as production accuracy.")


if __name__ == "__main__":
    main()
