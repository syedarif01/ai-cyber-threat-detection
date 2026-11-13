"""Start the API against a disposable in-memory SQLite database for smoke tests."""

import argparse
import sys
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src import api  # noqa: E402
from src.database import Base  # noqa: E402
from src.models import ThreatAlert  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    api.SessionLocal = factory
    with factory() as db:
        db.add_all([
            ThreatAlert(
                source_ip="192.0.2.101", alert_type="Smoke Test Alert",
                severity="High", status="New", occurrence_count=1,
            ),
            ThreatAlert(
                source_ip="192.0.2.102", alert_type="Smoke Test Alert",
                severity="Medium", status="Investigating", occurrence_count=1,
            ),
        ])
        db.commit()

    # The smoke suite may exercise POST /detect without reading files or
    # writing events. Workflow persistence remains tested through HTTP.
    api.run_detection = lambda: []
    api.get_latest_incidents_for_ips = lambda _ips: []
    api.get_last_detection_warnings = lambda: []

    import uvicorn
    try:
        uvicorn.run(api.app, host=args.host, port=args.port, log_level="error")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
