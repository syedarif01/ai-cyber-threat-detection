
from pathlib import Path

import pandas as pd

from detection_rules import detect_repeated_failed_logins

def main():
    project_root = Path(__file__).resolve().parent.parent
    log_file = project_root / "data" / "sample_logs.csv"

    logs = pd.read_csv(log_file)
    print(f"Total events loaded: {len(logs)}")

    alerts = detect_repeated_failed_logins(logs)

    print("\nSecurity alerts:")

    if not alerts:
        print("No alerts detected.")
        return

    for alert in alerts:
        print(alert)

if __name__ == "__main__":
    main()