"""Isolated API workflow checks using an in-memory SQLite database."""

import pytest
from starlette.requests import Request
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src import api
from src.api_security import role_for_key
from src.database import Base
from src.models import ThreatAlert


@pytest.fixture
def db_factory(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    monkeypatch.setattr(api, "SessionLocal", factory)
    yield factory
    engine.dispose()


@pytest.fixture
def incident_id(db_factory):
    with db_factory() as db:
        incident = ThreatAlert(
            source_ip="192.0.2.10",
            alert_type="AI Cyber Threat Detection",
            severity="High",
            status="New",
            occurrence_count=1,
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)
        return incident.id


def test_health_endpoint_is_available():
    assert api.health_check()["status"] == "healthy"


def test_public_and_identity_endpoint_handlers(monkeypatch):
    monkeypatch.delenv("CYBERGUARD_ANALYST_API_KEY", raising=False)
    monkeypatch.delenv("CYBERGUARD_VIEWER_API_KEY", raising=False)
    assert api.home()["version"] == "1.4.0"
    assert api.auth_status() == {"authentication_required": False}

    request = Request({"type": "http", "method": "GET", "path": "/auth/me", "headers": [], "state": {"role": "viewer"}})
    assert api.auth_me(request) == {"role": "viewer", "analyst_name": "Security Analyst"}


def test_detection_status_reads_current_incidents(monkeypatch):
    monkeypatch.setattr(
        api,
        "get_database_alerts",
        lambda limit: [
            {"id": 1, "status": "New"},
            {"id": 2, "status": "Resolved"},
        ],
    )
    result = api.get_detection_status()
    assert result["total_alerts"] == 1
    assert result["alerts"] == [{"id": 1, "status": "New"}]


def test_response_action_create_approve_simulate_and_audit(db_factory, incident_id):
    created = api.create_response_action(
        incident_id,
        api.ResponseActionCreate(
            action_type="Investigate Source IP",
            description="Review the authentication activity",
        ),
    )["response_action"]
    assert created["approval_status"] == "Pending"
    assert created["execution_status"] == "Not Executed"

    approved = api.decide_response_action(
        created["id"],
        api.ResponseDecision(decision="Approved"),
    )["response_action"]
    assert approved["approval_status"] == "Approved"
    assert approved["analyst_name"] == "Security Analyst"

    simulated = api.simulate_response_action(created["id"])["response_action"]
    assert simulated["execution_status"] == "Simulated"
    assert simulated["execution_mode"] == "Simulation"
    assert simulated["executed_at"] is not None

    audit = api.get_audit_logs(entity_type="ResponseAction", limit=20)
    assert [entry["action"] for entry in audit["audit_logs"]] == [
        "Response Action Simulated",
        "Response Action Approved",
        "Response Action Created",
    ]
    assert {entry["entity_id"] for entry in audit["audit_logs"]} == {created["id"]}
    latest = audit["audit_logs"][0]
    assert latest["entity_type"] == "ResponseAction"
    assert latest["analyst_name"] == "Security Analyst"
    assert latest["details"]
    assert latest["created_at"] is not None


def test_rejected_action_cannot_be_simulated(db_factory, incident_id):
    created = api.create_response_action(
        incident_id,
        api.ResponseActionCreate(action_type="Review Authentication Logs"),
    )["response_action"]
    rejected = api.decide_response_action(
        created["id"],
        api.ResponseDecision(decision="Rejected"),
    )["response_action"]

    assert rejected["approval_status"] == "Rejected"
    assert rejected["execution_status"] == "Rejected"
    with pytest.raises(api.HTTPException) as error:
        api.simulate_response_action(created["id"])
    assert error.value.status_code == 400


def test_invalid_decision_and_unknown_incident_are_rejected(db_factory):
    with pytest.raises(ValidationError):
        api.ResponseDecision(decision="Maybe")

    with pytest.raises(api.HTTPException) as missing_incident:
        api.create_response_action(
            999,
            api.ResponseActionCreate(action_type="Investigate Source IP"),
        )
    assert missing_incident.value.status_code == 404


def test_incident_status_update_is_audited(db_factory, incident_id):
    updated = api.update_alert_status(
        incident_id,
        api.StatusUpdate(status="Acknowledged"),
    )["alert"]
    assert updated["status"] == "Acknowledged"
    assert updated["acknowledged_at"] is not None

    audit = api.get_audit_logs(entity_type="ThreatAlert", limit=20)
    assert audit["total_logs"] == 1
    assert audit["audit_logs"][0]["action"] == "Incident Status Updated"
    assert audit["audit_logs"][0]["analyst_name"] == "Security Analyst"


def test_analyst_notes_append_and_are_audited(db_factory, incident_id):
    first = api.add_analyst_note(incident_id, api.AnalystNote(note="Reviewed login pattern"))
    second = api.add_analyst_note(incident_id, api.AnalystNote(note="Escalated for review"))

    assert "Reviewed login pattern" in first["alert"]["analyst_notes"]
    assert "Reviewed login pattern" in second["alert"]["analyst_notes"]
    assert "Escalated for review" in second["alert"]["analyst_notes"]
    audit = api.get_audit_logs(entity_type="ThreatAlert", limit=20)
    assert [item["action"] for item in audit["audit_logs"]] == [
        "Analyst Note Added",
        "Analyst Note Added",
    ]


def test_request_schemas_reject_invalid_and_extra_fields():
    with pytest.raises(ValueError):
        api.AnalystNote(note="   ")
    with pytest.raises(ValueError):
        api.ResponseActionCreate(action_type="Run Shell Command")
    with pytest.raises(ValueError):
        api.ResponseDecision(decision="Maybe")
    with pytest.raises(ValueError):
        api.StatusUpdate(status="Closed", unexpected="value")


def test_api_keys_separate_analyst_and_viewer_roles():
    assert role_for_key("analyst-secret", "analyst-secret", "viewer-secret") == "analyst"
    assert role_for_key("viewer-secret", "analyst-secret", "viewer-secret") == "viewer"
    assert role_for_key("wrong-secret", "analyst-secret", "viewer-secret") is None
    assert role_for_key(None, "analyst-secret", "viewer-secret") is None


def test_read_endpoints_return_persisted_incident_and_actions(db_factory, incident_id):
    created = api.create_response_action(
        incident_id,
        api.ResponseActionCreate(action_type="Investigate Source IP"),
    )["response_action"]

    history = api.alert_history(limit=10)
    details = api.get_alert_details(incident_id)
    per_incident = api.get_alert_response_actions(incident_id)
    all_actions = api.get_all_response_actions(limit=10)

    assert history["total_alerts"] == 1
    assert details["alert"]["id"] == incident_id
    assert per_incident["response_actions"][0]["id"] == created["id"]
    assert all_actions["response_actions"][0]["id"] == created["id"]


def test_missing_alert_detail_and_actions_return_not_found(db_factory):
    with pytest.raises(api.HTTPException) as detail_error:
        api.get_alert_details(999)
    assert detail_error.value.status_code == 404

    with pytest.raises(api.HTTPException) as actions_error:
        api.get_alert_response_actions(999)
    assert actions_error.value.status_code == 404


def test_cors_is_limited_to_local_frontend_origins():
    cors = next(middleware for middleware in api.app.user_middleware if middleware.cls.__name__ == "CORSMiddleware")
    assert cors.kwargs["allow_origins"] == [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]
    assert cors.kwargs["allow_methods"] == ["GET", "POST", "PATCH", "OPTIONS"]


def test_audit_limit_validation():
    with pytest.raises(api.HTTPException) as error:
        api.get_audit_logs(limit=501)
    assert error.value.status_code == 400


@pytest.mark.parametrize("limit", [0, -1, 501])
def test_history_and_action_limits_reject_out_of_range_values(limit):
    with pytest.raises(api.HTTPException) as history_error:
        api.alert_history(limit=limit)
    assert history_error.value.status_code == 400

    with pytest.raises(api.HTTPException) as action_error:
        api.get_all_response_actions(limit=limit)
    assert action_error.value.status_code == 400


def test_detection_endpoint_returns_runtime_warnings(monkeypatch):
    warning = "ML classifier unavailable; this run used rule-based detections only."
    monkeypatch.setattr(api, "run_detection", lambda: [])
    monkeypatch.setattr(api, "get_last_detection_warnings", lambda: [warning])
    monkeypatch.setattr(api, "get_latest_incidents_for_ips", lambda _ips: [])

    result = api.execute_detection()

    assert result["warnings"] == [warning]
    assert result["total_alerts"] == 0
