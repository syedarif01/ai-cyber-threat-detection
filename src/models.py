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

    # Structured alert information
    failed_attempts = Column(Integer, nullable=True)
    ml_prediction = Column(String(50), nullable=True)
    detection_methods = Column(Text, nullable=True)

    # Incident correlation information
    occurrence_count = Column(
        Integer,
        nullable=False,
        default=1,
        server_default="1"
    )

    last_seen_at = Column(
        DateTime,
        nullable=True
    )

    # Incident management information
    status = Column(
        String(30),
        nullable=False,
        default="New",
        server_default="New"
    )

    analyst_notes = Column(Text, nullable=True)

    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    created_at = Column(
        DateTime,
        server_default=func.now()
    )


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True, index=True)

    # Related security incident
    alert_id = Column(Integer, nullable=False, index=True)

    source_ip = Column(String(50), nullable=False)

    # Response information
    action_type = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)

    # Approval information
    approval_status = Column(
        String(30),
        nullable=False,
        default="Pending",
        server_default="Pending"
    )

    # Execution information
    execution_status = Column(
        String(30),
        nullable=False,
        default="Not Executed",
        server_default="Not Executed"
    )

    execution_mode = Column(
        String(30),
        nullable=False,
        default="Simulation",
        server_default="Simulation"
    )

    analyst_name = Column(String(100), nullable=True)

    created_at = Column(
        DateTime,
        server_default=func.now()
    )

    executed_at = Column(DateTime, nullable=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    # Activity information
    action = Column(String(100), nullable=False)
    entity_type = Column(String(50), nullable=False)

    # Related incident or response action ID
    entity_id = Column(Integer, nullable=True)

    # Analyst information
    analyst_name = Column(
        String(100),
        nullable=True
    )

    # Additional activity details
    details = Column(Text, nullable=True)

    # Activity timestamp
    created_at = Column(
        DateTime,
        nullable=False,
        server_default=func.now()
    )