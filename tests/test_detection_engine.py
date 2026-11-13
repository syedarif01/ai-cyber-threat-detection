"""End-to-end detection checks with isolated, in-memory persistence."""

from pathlib import Path

import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src import detection_engine
from src.database import Base
from src.models import SecurityEvent, ThreatAlert


def test_sample_log_detection_persists_once_and_ignores_replays(monkeypatch):
    project_root = Path(__file__).resolve().parents[1]
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    monkeypatch.setattr(detection_engine, "SessionLocal", factory)
    monkeypatch.setattr(
        detection_engine,
        "LOG_FILE",
        project_root / "data" / "sample_logs.csv",
    )
    monkeypatch.setattr(
        detection_engine,
        "predict_activity",
        lambda failed_attempts, **_features: {
            "prediction": "Unavailable",
            "severity": "Unknown",
            "model_available": False,
        },
    )

    logs_count = len(pd.read_csv(detection_engine.LOG_FILE))
    first_run = detection_engine.run_detection()
    with factory() as db:
        assert db.query(SecurityEvent).count() == logs_count
        first_incident_count = db.query(ThreatAlert).count()
        first_occurrences = {
            (alert.source_ip, alert.alert_type): alert.occurrence_count
            for alert in db.query(ThreatAlert).all()
        }

    second_run = detection_engine.run_detection()
    with factory() as db:
        assert db.query(SecurityEvent).count() == logs_count
        assert db.query(ThreatAlert).count() == first_incident_count
        assert {
            (alert.source_ip, alert.alert_type): alert.occurrence_count
            for alert in db.query(ThreatAlert).all()
        } == first_occurrences

    assert isinstance(first_run, list)
    assert isinstance(second_run, list)
    assert detection_engine.get_last_detection_warnings() == [
        "ML classifier unavailable; this run used rule-based detections only."
    ]
    engine.dispose()
