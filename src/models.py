from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func

from .database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False)
    username = Column(String(100))
    source_ip = Column(String(50), nullable=False)
    event_type = Column(String(50), nullable=False)
    status = Column(String(30), nullable=False)


class ThreatAlert(Base):
    __tablename__ = "threat_alerts"

    id = Column(Integer, primary_key=True, index=True)

    source_ip = Column(String(50), nullable=False)
    alert_type = Column(String(100), nullable=False)
    severity = Column(String(30), nullable=False)
    description = Column(Text)

    # Additional structured alert information
    failed_attempts = Column(Integer, nullable=True)
    ml_prediction = Column(String(50), nullable=True)
    detection_methods = Column(Text, nullable=True)

    created_at = Column(
        DateTime,
        server_default=func.now()
    )