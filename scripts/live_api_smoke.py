"""Exercise the API over HTTP using a disposable in-memory SQLite server.

No requests from this smoke test can write to the configured PostgreSQL DB.
"""

import json
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")


def main() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    # Use short-lived in-process credentials so the smoke test always exercises
    # both roles without reading, printing, or changing the user's real keys.
    analyst_key = secrets.token_urlsafe(32)
    viewer_key = secrets.token_urlsafe(32)
    env["CYBERGUARD_ANALYST_API_KEY"] = analyst_key
    env["CYBERGUARD_VIEWER_API_KEY"] = viewer_key
    process = subprocess.Popen(
        [sys.executable, str(ROOT / "scripts" / "isolated_api_server.py"), "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    failures = []

    def send(method: str, path: str, payload=None, key=analyst_key, headers=None):
        request_headers = dict(headers or {})
        if key:
            request_headers["Authorization"] = f"Bearer {key}"
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        if data is not None:
            request_headers["Content-Type"] = "application/json"
        request = Request(base_url + path, data=data, method=method, headers=request_headers)
        try:
            with urlopen(request, timeout=4) as response:
                return response.status, response.headers, response.read()
        except HTTPError as error:
            return error.code, error.headers, error.read()

    def expect(label, actual, expected):
        ok = actual == expected
        print(f"{'PASS' if ok else 'FAIL'} {label}: HTTP {actual}, expected {expected}")
        if not ok:
            failures.append(label)

    try:
        ready = False
        for _ in range(60):
            if process.poll() is not None:
                break
            try:
                if send("GET", "/health", key=None)[0] == 200:
                    ready = True
                    break
            except (URLError, TimeoutError):
                time.sleep(0.1)
        if not ready:
            server_output = process.stdout.read() if process.stdout else ""
            print("FAIL local API startup")
            if server_output:
                print(server_output[-4000:])
            return 1

        for route in ["/", "/health", "/auth/me", "/detect", "/history?limit=2", "/audit-logs?limit=2", "/response-actions?limit=2", "/docs", "/redoc", "/openapi.json"]:
            expect(f"GET {route}", send("GET", route)[0], 200)

        expect("GET /auth/status", send("GET", "/auth/status", key=None)[0], 200)
        history_body = json.loads(send("GET", "/history?limit=2")[2])
        alert_id = history_body["alerts"][0]["id"]
        reject_alert_id = history_body["alerts"][1]["id"]
        expect("GET /alerts/{alert_id}", send("GET", f"/alerts/{alert_id}")[0], 200)

        create_status, _, created_body = send(
            "POST", f"/alerts/{alert_id}/response-actions",
            {"action_type": "Investigate Source IP", "description": "Isolated HTTP workflow"},
        )
        expect("POST create response action", create_status, 200)
        action_id = json.loads(created_body)["response_action"]["id"]
        expect("PATCH approve response action", send("PATCH", f"/response-actions/{action_id}/decision", {"decision": "Approved"})[0], 200)
        simulated_status, _, simulated_body = send("POST", f"/response-actions/{action_id}/simulate")
        expect("POST simulate approved action", simulated_status, 200)
        expect("Simulation is recorded", json.loads(simulated_body)["response_action"]["execution_status"], "Simulated")

        reject_status, _, rejected_body = send(
            "POST", f"/alerts/{reject_alert_id}/response-actions",
            {"action_type": "Review Authentication Logs"},
        )
        expect("POST create action for rejection", reject_status, 200)
        rejected_id = json.loads(rejected_body)["response_action"]["id"]
        expect("PATCH reject response action", send("PATCH", f"/response-actions/{rejected_id}/decision", {"decision": "Rejected"})[0], 200)
        expect("Rejected action cannot be simulated", send("POST", f"/response-actions/{rejected_id}/simulate")[0], 400)
        expect("GET /alerts/{alert_id}/response-actions", send("GET", f"/alerts/{alert_id}/response-actions")[0], 200)
        actions_status, _, actions_body = send("GET", "/response-actions?limit=10")
        expect("GET persisted response actions", actions_status, 200)
        persisted_actions = json.loads(actions_body)["response_actions"]
        persisted_states = {(item["approval_status"], item["execution_status"]) for item in persisted_actions}
        for state in [("Approved", "Simulated"), ("Rejected", "Rejected")]:
            print(f"{'PASS' if state in persisted_states else 'FAIL'} persisted action state {state}")
            if state not in persisted_states:
                failures.append(f"persisted action state {state}")

        expect("PATCH incident status", send("PATCH", f"/alerts/{alert_id}/status", {"status": "Acknowledged"})[0], 200)
        expect("PATCH append analyst note", send("PATCH", f"/alerts/{alert_id}/notes", {"note": "Smoke test note"})[0], 200)
        detail_status, _, detail_body = send("GET", f"/alerts/{alert_id}")
        expect("GET persisted status and note", detail_status, 200)
        persisted_alert = json.loads(detail_body)["alert"]
        if persisted_alert.get("status") != "Acknowledged" or "Smoke test note" not in (persisted_alert.get("analyst_notes") or ""):
            failures.append("persisted incident status/note")
            print("FAIL incident status or note was not persisted")
        else:
            print("PASS incident status and note persisted")
        audit_status, _, audit_body = send("GET", "/audit-logs?limit=20")
        expect("GET workflow audit history", audit_status, 200)
        audit_data = json.loads(audit_body)
        audit_actions = {entry["action"] for entry in audit_data["audit_logs"]}
        created_audit = next(
            (entry for entry in audit_data["audit_logs"] if entry.get("entity_id") == action_id and entry.get("action") == "Response Action Created"),
            None,
        )
        audit_fields_ok = bool(
            created_audit
            and created_audit.get("entity_type") == "ResponseAction"
            and created_audit.get("analyst_name")
            and created_audit.get("details")
            and created_audit.get("created_at")
        )
        print(f"{'PASS' if audit_fields_ok else 'FAIL'} audit action/entity/analyst/details/timestamp fields")
        if not audit_fields_ok:
            failures.append("audit required fields")
        for expected_action in ["Response Action Created", "Response Action Approved", "Response Action Rejected", "Response Action Simulated", "Incident Status Updated", "Analyst Note Added"]:
            print(f"{'PASS' if expected_action in audit_actions else 'FAIL'} audit includes {expected_action}")
            if expected_action not in audit_actions:
                failures.append(f"audit {expected_action}")

        expect("POST /detect safe stub", send("POST", "/detect", {})[0], 200)

        for route in ["/history?limit=501", "/audit-logs?limit=501", "/response-actions?limit=501"]:
            expect(f"GET {route} invalid limit", send("GET", route)[0], 400)
        expect("POST response action invalid schema", send("POST", "/alerts/1/response-actions", {"action_type": "Run Command"})[0], 422)
        expect("PATCH status invalid schema", send("PATCH", "/alerts/1/status", {"status": "Closed"})[0], 422)
        expect("PATCH notes invalid schema", send("PATCH", "/alerts/1/notes", {"note": "   "})[0], 422)
        expect("PATCH decision invalid schema", send("PATCH", "/response-actions/999999/decision", {"decision": "Maybe"})[0], 422)
        expect("POST simulate unknown action", send("POST", "/response-actions/999999/simulate")[0], 404)

        if analyst_key or viewer_key:
            expect("GET history without a key", send("GET", "/history", key=None)[0], 401)
            expect("GET history with invalid key", send("GET", "/history", key="invalid-key")[0], 401)
        if viewer_key:
            viewer_write_checks = [
                ("POST /detect", "POST", "/detect", {}),
                ("PATCH incident status", "PATCH", f"/alerts/{alert_id}/status", {"status": "Acknowledged"}),
                ("PATCH analyst note", "PATCH", f"/alerts/{alert_id}/notes", {"note": "Viewer must not write"}),
                ("POST response action", "POST", f"/alerts/{alert_id}/response-actions", {"action_type": "Review Authentication Logs"}),
                ("PATCH response decision", "PATCH", f"/response-actions/{action_id}/decision", {"decision": "Rejected"}),
                ("POST response simulation", "POST", f"/response-actions/{action_id}/simulate", None),
            ]
            for label, method, route, payload in viewer_write_checks:
                expect(f"Viewer cannot write via {label}", send(method, route, payload, key=viewer_key)[0], 403)

        status, response_headers, _ = send(
            "OPTIONS", "/history", key=None,
            headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"},
        )
        expect("CORS preflight", status, 200)
        expect("CORS allowed origin", response_headers.get("Access-Control-Allow-Origin"), "http://localhost:5173")
        _, denied_origin_headers, _ = send(
            "OPTIONS", "/history", key=None,
            headers={"Origin": "https://unapproved.example", "Access-Control-Request-Method": "GET"},
        )
        expect("CORS rejects unapproved origin", denied_origin_headers.get("Access-Control-Allow-Origin"), None)

        print(f"HTTP smoke checks: {len(failures)} failure(s)")
        return 1 if failures else 0
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
