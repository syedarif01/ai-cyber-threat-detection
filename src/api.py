
import json
import logging
from datetime import datetime, timezone
import ipaddress
import os
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session
from starlette.requests import Request
from starlette.responses import JSONResponse

from src.database import SessionLocal
from src.detection_engine import run_detection, get_last_detection_warnings
from src.database_service import get_alert_history
from src.models import ThreatAlert, ResponseAction, AuditLog
from src.api_security import access_keys_configured, role_for_key


app = FastAPI(
    title="AI Cyber Threat Detection API",
    description="AI-powered cybersecurity threat detection and incident management",
    version="1.4.0"
)
logger = logging.getLogger(__name__)


# --------------------------------------------------
# CORS CONFIGURATION
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


@app.middleware("http")
async def enforce_api_access(request, call_next):
    if request.method == "OPTIONS" or request.url.path in {"/", "/health", "/auth/status"}:
        return await call_next(request)

    if not access_keys_configured():
        host = request.client.host if request.client else ""
        try:
            is_local = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_local = host == "testclient"
        if not is_local:
            return JSONResponse(
                status_code=503,
                content={"detail": "Configure API keys before exposing this service beyond localhost."},
            )
        request.state.role = "analyst"
        return await call_next(request)

    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")
    role = role_for_key(token if scheme.lower() == "bearer" else None)
    if not role:
        return JSONResponse(status_code=401, content={"detail": "Valid bearer API key required."})
    if role == "viewer" and request.method not in {"GET", "HEAD", "OPTIONS"}:
        return JSONResponse(status_code=403, content={"detail": "Viewer access is read-only."})
    request.state.role = role
    return await call_next(request)


# --------------------------------------------------
# CONSTANTS
# --------------------------------------------------

ACTIVE_STATUSES = [
    "New",
    "Acknowledged",
    "Investigating"
]

ALLOWED_RESPONSE_ACTIONS = [
    "Investigate Source IP",
    "Review Authentication Logs",
    "Monitor Suspicious Activity",
    "Temporarily Block IP",
    "Require Password Reset"
]

ALLOWED_DECISIONS = [
    "Approved",
    "Rejected"
]

def configured_analyst_name() -> str:
    return os.getenv("CYBERGUARD_ANALYST_NAME", "Security Analyst")[:100]


# --------------------------------------------------
# REQUEST SCHEMAS
# --------------------------------------------------

class StatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["New", "Acknowledged", "Investigating", "Resolved"]


class AnalystNote(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: str = Field(
        min_length=1,
        max_length=5000,
        strict=True,
    )

    @field_validator("note")
    @classmethod
    def note_must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Note must not be blank")
        return value


class ResponseActionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: Literal[
        "Investigate Source IP",
        "Review Authentication Logs",
        "Monitor Suspicious Activity",
        "Temporarily Block IP",
        "Require Password Reset",
    ]
    description: Optional[str] = Field(default=None, max_length=2000, strict=True)


class ResponseDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["Approved", "Rejected"]


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def current_time():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# --------------------------------------------------
# AUDIT LOG HELPER
# --------------------------------------------------

def record_audit_log(
    db: Session,
    action: str,
    entity_type: str,
    entity_id: Optional[int] = None,
    analyst_name: Optional[str] = None,
    details: Optional[str] = None
):
    audit_entry = AuditLog(
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        analyst_name=analyst_name,
        details=details
    )

    db.add(audit_entry)

    return audit_entry


@app.get("/audit-logs")
def get_audit_logs(entity_type: Optional[str] = None, limit: int = 100):
    """Return recent audit records, optionally scoped to one entity type."""
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="Limit must be between 1 and 500")

    db: Session = SessionLocal()
    try:
        query = db.query(AuditLog)
        if entity_type:
            query = query.filter(AuditLog.entity_type == entity_type)
        records = query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(limit).all()
        return {
            "total_logs": len(records),
            "audit_logs": [
                {
                    "id": item.id,
                    "action": item.action,
                    "entity_type": item.entity_type,
                    "entity_id": item.entity_id,
                    "analyst_name": item.analyst_name,
                    "details": item.details,
                    "created_at": item.created_at,
                }
                for item in records
            ],
        }
    finally:
        db.close()


def serialize_detection_methods(value):

    if not value:
        return []

    if isinstance(value, list):
        return value

    try:
        parsed = json.loads(value)

        if isinstance(parsed, list):
            return parsed

        return []

    except (json.JSONDecodeError, TypeError):
        return []


def alert_to_dict(alert: ThreatAlert):

    return {
        "id": alert.id,
        "source_ip": alert.source_ip,
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "description": alert.description,
        "failed_attempts": alert.failed_attempts,
        "ml_prediction": alert.ml_prediction,

        "detection_methods": serialize_detection_methods(
            alert.detection_methods
        ),

        "occurrence_count": alert.occurrence_count,
        "last_seen_at": alert.last_seen_at,

        "status": alert.status,
        "analyst_notes": alert.analyst_notes,

        "acknowledged_at": alert.acknowledged_at,
        "resolved_at": alert.resolved_at,
        "created_at": alert.created_at
    }


def response_action_to_dict(action: ResponseAction):

    return {
        "id": action.id,
        "alert_id": action.alert_id,
        "source_ip": action.source_ip,
        "action_type": action.action_type,
        "description": action.description,
        "approval_status": action.approval_status,
        "execution_status": action.execution_status,
        "execution_mode": action.execution_mode,
        "analyst_name": action.analyst_name,
        "created_at": action.created_at,
        "executed_at": action.executed_at
    }


def get_database_alerts(limit=100):

    db: Session = SessionLocal()

    try:
        alerts = get_alert_history(db, limit)
        return alerts

    finally:
        db.close()


def get_latest_incidents_for_ips(source_ips):

    if not source_ips:
        return []

    db: Session = SessionLocal()

    try:
        records = (
            db.query(ThreatAlert)
            .filter(
                ThreatAlert.source_ip.in_(source_ips),
                ThreatAlert.alert_type == "AI Cyber Threat Detection"
            )
            .order_by(
                ThreatAlert.created_at.desc(),
                ThreatAlert.id.desc()
            )
            .all()
        )

        latest_by_ip = {}

        for record in records:
            if record.source_ip not in latest_by_ip:
                latest_by_ip[record.source_ip] = alert_to_dict(record)

        return list(latest_by_ip.values())

    finally:
        db.close()


# --------------------------------------------------
# BASIC ENDPOINTS
# --------------------------------------------------

@app.get("/")
def home():

    return {
        "message": "AI Cyber Threat Detection API is running",
        "version": "1.4.0"
    }


@app.get("/health")
def health_check():

    return {
        "status": "healthy",
        "service": "AI Cyber Threat Detection API"
    }


@app.get("/auth/status")
def auth_status():
    return {"authentication_required": access_keys_configured()}


@app.get("/auth/me")
def auth_me(request: Request):
    return {
        "role": getattr(request.state, "role", "analyst"),
        "analyst_name": os.getenv("CYBERGUARD_ANALYST_NAME", "Security Analyst"),
    }


# --------------------------------------------------
# DETECTION ENDPOINTS
# --------------------------------------------------

@app.get("/detect")
def get_detection_status():

    alerts = get_database_alerts(limit=100)

    active_alerts = [
        alert
        for alert in alerts
        if alert.get("status") in ACTIVE_STATUSES
    ]

    return {
        "message": "Read-only endpoint. Use POST /detect to run detection.",
        "total_alerts": len(active_alerts),
        "alerts": active_alerts
    }


@app.post("/detect")
def execute_detection():

    try:
        live_alerts = run_detection()

        source_ips = {
            alert.get("source_ip")
            for alert in live_alerts
            if alert.get("source_ip")
        }

        database_alerts = get_latest_incidents_for_ips(source_ips)

        return {
            "message": "Threat detection completed successfully",
            "warnings": get_last_detection_warnings(),
            "total_alerts": len(database_alerts),
            "alerts": database_alerts
        }

    except Exception:
        logger.exception("Threat detection failed")
        raise HTTPException(
            status_code=500,
            detail="Detection failed. Check the backend log for details."
        )


# --------------------------------------------------
# ALERT HISTORY
# --------------------------------------------------

@app.get("/history")
def alert_history(limit: int = 100):

    if limit < 1 or limit > 500:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 500"
        )

    alerts = get_database_alerts(limit)

    return {
        "total_alerts": len(alerts),
        "alerts": alerts
    }


# --------------------------------------------------
# ALERT DETAILS
# --------------------------------------------------

@app.get("/alerts/{alert_id}")
def get_alert_details(alert_id: int):

    db: Session = SessionLocal()

    try:
        alert = (
            db.query(ThreatAlert)
            .filter(ThreatAlert.id == alert_id)
            .first()
        )

        if not alert:
            raise HTTPException(
                status_code=404,
                detail="Alert not found"
            )

        return {
            "alert": alert_to_dict(alert)
        }

    finally:
        db.close()


# --------------------------------------------------
# CREATE RESPONSE ACTION
# --------------------------------------------------

@app.post("/alerts/{alert_id}/response-actions")
def create_response_action(
    alert_id: int,
    action_data: ResponseActionCreate
):

    if action_data.action_type not in ALLOWED_RESPONSE_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported response action"
        )

    db: Session = SessionLocal()

    try:
        alert = (
            db.query(ThreatAlert)
            .filter(ThreatAlert.id == alert_id)
            .first()
        )

        if not alert:
            raise HTTPException(
                status_code=404,
                detail="Alert not found"
            )

        action = ResponseAction(
            alert_id=alert.id,
            source_ip=alert.source_ip,
            action_type=action_data.action_type,
            description=action_data.description,
            approval_status="Pending",
            execution_status="Not Executed",
            execution_mode="Simulation"
        )

        db.add(action)

        # Generate the response-action ID
        db.flush()

        # Record action creation in audit history
        record_audit_log(
            db=db,
            action="Response Action Created",
            entity_type="ResponseAction",
            entity_id=action.id,
            analyst_name=configured_analyst_name(),
            details=(
                f"Created '{action.action_type}' "
                f"for incident #{alert.id}, "
                f"source IP {alert.source_ip}."
            )
        )

        db.commit()
        db.refresh(action)

        return {
            "message": "Response action created successfully",
            "response_action": response_action_to_dict(action)
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


# --------------------------------------------------
# UPDATE INCIDENT STATUS
# --------------------------------------------------

@app.patch("/alerts/{alert_id}/status")
def update_alert_status(
    alert_id: int,
    update: StatusUpdate
):

    allowed_statuses = [
        "New",
        "Acknowledged",
        "Investigating",
        "Resolved"
    ]

    if update.status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail="Invalid status"
        )

    db: Session = SessionLocal()

    try:
        alert = (
            db.query(ThreatAlert)
            .filter(ThreatAlert.id == alert_id)
            .first()
        )

        if not alert:
            raise HTTPException(
                status_code=404,
                detail="Alert not found"
            )

        previous_status = alert.status

        alert.status = update.status

        if update.status == "Acknowledged":
            if not alert.acknowledged_at:
                alert.acknowledged_at = current_time()

        elif update.status == "Resolved":
            alert.resolved_at = current_time()

        else:
            alert.resolved_at = None

        # Record activity in audit history
        record_audit_log(
            db=db,
            action="Incident Status Updated",
            entity_type="ThreatAlert",
            entity_id=alert.id,
            analyst_name=configured_analyst_name(),
            details=(
                f"Incident status changed from "
                f"{previous_status} to {update.status} "
                f"for source IP {alert.source_ip}."
            )
        )

        db.commit()
        db.refresh(alert)

        return {
            "message": "Incident status updated successfully",
            "alert": alert_to_dict(alert)
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


@app.patch("/alerts/{alert_id}/notes")
def add_analyst_note(alert_id: int, note_data: AnalystNote):
    """Append a validated analyst note and record the change in audit history."""
    db: Session = SessionLocal()
    try:
        alert = db.query(ThreatAlert).filter(ThreatAlert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        timestamp = current_time().isoformat(timespec="seconds")
        entry = f"[{timestamp}] {note_data.note}"
        alert.analyst_notes = (
            f"{alert.analyst_notes}\n\n{entry}"
            if alert.analyst_notes
            else entry
        )
        record_audit_log(
            db=db,
            action="Analyst Note Added",
            entity_type="ThreatAlert",
            entity_id=alert.id,
        analyst_name=configured_analyst_name(),
            details=f"Analyst note added to incident #{alert.id}.",
        )
        db.commit()
        db.refresh(alert)
        return {"message": "Analyst note saved successfully", "alert": alert_to_dict(alert)}
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# --------------------------------------------------
# VIEW RESPONSE ACTIONS FOR AN INCIDENT
# --------------------------------------------------

@app.get("/alerts/{alert_id}/response-actions")
def get_alert_response_actions(alert_id: int):

    db: Session = SessionLocal()

    try:
        alert = (
            db.query(ThreatAlert)
            .filter(ThreatAlert.id == alert_id)
            .first()
        )

        if not alert:
            raise HTTPException(
                status_code=404,
                detail="Alert not found"
            )

        actions = (
            db.query(ResponseAction)
            .filter(ResponseAction.alert_id == alert_id)
            .order_by(ResponseAction.created_at.desc())
            .all()
        )

        return {
            "alert_id": alert_id,
            "total_actions": len(actions),
            "response_actions": [
                response_action_to_dict(action)
                for action in actions
            ]
        }

    finally:
        db.close()


# --------------------------------------------------
# VIEW ALL RESPONSE ACTIONS
# --------------------------------------------------

@app.get("/response-actions")
def get_all_response_actions(limit: int = 100):

    if limit < 1 or limit > 500:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 500"
        )

    db: Session = SessionLocal()

    try:
        actions = (
            db.query(ResponseAction)
            .order_by(ResponseAction.created_at.desc())
            .limit(limit)
            .all()
        )

        return {
            "total_actions": len(actions),
            "response_actions": [
                response_action_to_dict(action)
                for action in actions
            ]
        }

    finally:
        db.close()


# --------------------------------------------------
# APPROVE OR REJECT RESPONSE ACTION
# --------------------------------------------------

@app.patch("/response-actions/{action_id}/decision")
def decide_response_action(
    action_id: int,
    decision_data: ResponseDecision
):

    if decision_data.decision not in ALLOWED_DECISIONS:
        raise HTTPException(
            status_code=400,
            detail="Decision must be Approved or Rejected"
        )

    db: Session = SessionLocal()

    try:
        action = (
            db.query(ResponseAction)
            .filter(ResponseAction.id == action_id)
            .first()
        )

        if not action:
            raise HTTPException(
                status_code=404,
                detail="Response action not found"
            )

        if action.execution_status != "Not Executed":
            raise HTTPException(
                status_code=400,
                detail="This response action has already been processed"
            )

        if action.approval_status != "Pending":
            raise HTTPException(
                status_code=400,
                detail="A decision has already been recorded"
            )

        action.approval_status = decision_data.decision
        action.analyst_name = configured_analyst_name()

        if decision_data.decision == "Rejected":
            action.execution_status = "Rejected"

        # Record approval or rejection in audit history
        record_audit_log(
            db=db,
            action=f"Response Action {decision_data.decision}",
            entity_type="ResponseAction",
            entity_id=action.id,
            analyst_name=configured_analyst_name(),
            details=(
                f"{decision_data.decision} response action "
                f"'{action.action_type}' for incident #{action.alert_id}, "
                f"source IP {action.source_ip}."
            )
        )

        db.commit()
        db.refresh(action)

        return {
            "message": (
                f"Response action {decision_data.decision.lower()} successfully"
            ),
            "response_action": response_action_to_dict(action)
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


# --------------------------------------------------
# SIMULATE APPROVED RESPONSE ACTION
# --------------------------------------------------

@app.post("/response-actions/{action_id}/simulate")
def simulate_response_action(action_id: int):

    db: Session = SessionLocal()

    try:
        action = (
            db.query(ResponseAction)
            .filter(ResponseAction.id == action_id)
            .first()
        )

        if not action:
            raise HTTPException(
                status_code=404,
                detail="Response action not found"
            )

        if action.approval_status != "Approved":
            raise HTTPException(
                status_code=400,
                detail="Response action must be approved first"
            )

        if action.execution_status != "Not Executed":
            raise HTTPException(
                status_code=400,
                detail="Response action has already been executed or processed"
            )

        # Update simulation details
        action.execution_mode = "Simulation"
        action.execution_status = "Simulated"
        action.executed_at = current_time()

        # Record simulation in audit logs
        record_audit_log(
            db=db,
            action="Response Action Simulated",
            entity_type="ResponseAction",
            entity_id=action.id,
            analyst_name=action.analyst_name or configured_analyst_name(),
            details=(
                f"Simulated response action '{action.action_type}' "
                f"for incident #{action.alert_id}, "
                f"source IP {action.source_ip}. "
                "No real network changes were made."
            )
        )

        # Save both changes together
        db.commit()
        db.refresh(action)

        return {
            "message": (
                "Response action simulated successfully. "
                "No real network changes were made."
            ),
            "response_action": response_action_to_dict(action)
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()
