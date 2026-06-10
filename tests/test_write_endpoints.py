"""Write-path tests for design-e RPC (audit F5 fix, 2026-06-10).

Pre-fix: only GET /rpc/v1/results was covered. The three write endpoints
(dispatch_specialist, hermes_ask, record_event) had ZERO test coverage,
meaning auth bypass, allow-list bypass, and rate-limit regression all
shipped undetected. This file closes that gap.
"""
from __future__ import annotations

import json
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient

import design_e_endpoint as dee


def _token(secret: str = "test-secret", aud: str = "https://zenops-cloud-dispatch", upn: str = "Scout@test") -> str:
    return jwt.encode(
        {
            "sub": "scout",
            "aud": aud,
            "upn": upn,
            "tid": "test-tenant-id",
            "iss": "https://login.microsoftonline.com/test-tenant-id/v2.0",
        },
        secret,
        algorithm="HS256",
    )


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    results = tmp_path / "results"
    results.mkdir()
    audit = tmp_path / "audit"
    audit.mkdir()
    monkeypatch.setattr(dee, "BRAIN_INBOX_PATH", inbox, raising=False)
    monkeypatch.setattr(dee, "RESULTS_PATH", results, raising=False)
    monkeypatch.setattr(dee, "AUDIT_LOG_PATH", audit, raising=False)
    # Reset rate-limit log between tests
    dee.caller_request_log.clear()
    return TestClient(dee.app)


def _dispatch_body(specialist: str = "Scout") -> dict:
    return {
        "specialist": specialist,
        "task": {
            "id": None,
            "role": "research",
            "payload": {"q": "hello"},
            "priority": "normal",
            "ttl_sec": 3600,
        },
        "context": {
            "session_id": "s1",
            "user_id": "u1",
            "caller": "Scout",
        },
    }


# ---------------------------------------------------------------------------
# /rpc/v1/dispatch_specialist
# ---------------------------------------------------------------------------


def test_dispatch_rejects_missing_auth(client: TestClient, tmp_path: Path) -> None:
    """Missing JWT -> 401, NO inbox write (JWT-before-side-effects)."""
    resp = client.post("/rpc/v1/dispatch_specialist", json=_dispatch_body())
    assert resp.status_code == 401
    assert not list((tmp_path / "inbox").iterdir()), "inbox must be empty on auth failure"


def test_dispatch_rejects_invalid_jwt(client: TestClient, tmp_path: Path) -> None:
    """Bad JWT signature -> 401, NO inbox write."""
    bad = _token(secret="wrong-secret")
    resp = client.post(
        "/rpc/v1/dispatch_specialist",
        json=_dispatch_body(),
        headers={"Authorization": f"Bearer {bad}"},
    )
    assert resp.status_code == 401
    assert not list((tmp_path / "inbox").iterdir())


def test_dispatch_rejects_unknown_specialist(client: TestClient, tmp_path: Path) -> None:
    """Specialist not in allow-list -> 400, NO inbox write."""
    tok = _token()
    resp = client.post(
        "/rpc/v1/dispatch_specialist",
        json=_dispatch_body(specialist="NotAReal Specialist"),
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 400
    assert not list((tmp_path / "inbox").iterdir())


def test_dispatch_happy_path_writes_inbox(client: TestClient, tmp_path: Path) -> None:
    """Valid request -> 202, inbox file exists with expected envelope shape."""
    tok = _token()
    resp = client.post(
        "/rpc/v1/dispatch_specialist",
        json=_dispatch_body(),
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 202
    task_id = resp.json()["data"]["task_id"]
    inbox_file = tmp_path / "inbox" / f"{task_id}.json"
    assert inbox_file.exists()
    envelope = json.loads(inbox_file.read_text(encoding="utf-8"))
    assert envelope["specialist"] == "Scout"
    assert envelope["task"]["id"] == task_id
    assert "created_at" in envelope


def test_dispatch_rate_limit_returns_429_and_no_write(client: TestClient, tmp_path: Path) -> None:
    """Once quota exceeded -> 429 + no further inbox writes."""
    tok = _token(upn="Scout@test")  # Scout quota = 100/min
    # Pre-fill rate-limit log to be just over quota.
    import time
    now = time.time()
    dee.caller_request_log["Scout"] = [now] * 100
    pre_count = len(list((tmp_path / "inbox").iterdir()))
    resp = client.post(
        "/rpc/v1/dispatch_specialist",
        json=_dispatch_body(),
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 429
    post_count = len(list((tmp_path / "inbox").iterdir()))
    assert post_count == pre_count, "rate-limited dispatch must not write inbox"


# ---------------------------------------------------------------------------
# /rpc/v1/hermes_ask
# ---------------------------------------------------------------------------


def test_hermes_ask_rejects_missing_auth(client: TestClient) -> None:
    resp = client.post("/rpc/v1/hermes_ask", json={
        "query": "hi",
        "context": {"session_id": "s", "user_id": "u"},
    })
    assert resp.status_code == 401


def test_hermes_ask_rejects_query_too_long(client: TestClient) -> None:
    """Pydantic max_length=2000 -> 422 unprocessable entity."""
    tok = _token()
    resp = client.post(
        "/rpc/v1/hermes_ask",
        json={"query": "x" * 2001, "context": {"session_id": "s", "user_id": "u"}},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code in (400, 422)


def test_hermes_ask_happy_path(client: TestClient) -> None:
    tok = _token()
    resp = client.post(
        "/rpc/v1/hermes_ask",
        json={"query": "hi", "context": {"session_id": "s", "user_id": "u"}},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# /rpc/v1/record_event
# ---------------------------------------------------------------------------


def test_record_event_rejects_missing_auth(client: TestClient, tmp_path: Path) -> None:
    """Missing JWT -> 401, NO audit log write."""
    resp = client.post("/rpc/v1/record_event", json={
        "event_type": "dispatch_created",
        "task_id": "t1",
        "details": {},
        "context": {"session_id": "s", "user_id": "u"},
    })
    assert resp.status_code == 401
    assert not list((tmp_path / "audit").iterdir())


def test_record_event_rejects_bad_event_type(client: TestClient, tmp_path: Path) -> None:
    """event_type not in allow-list -> 400, NO audit log write."""
    tok = _token()
    resp = client.post(
        "/rpc/v1/record_event",
        json={
            "event_type": "totally_made_up",
            "task_id": "t1",
            "details": {},
            "context": {"session_id": "s", "user_id": "u"},
        },
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 400
    assert not list((tmp_path / "audit").iterdir())


def test_record_event_happy_path_writes_audit(client: TestClient, tmp_path: Path) -> None:
    """Valid request -> 204 + audit file appended."""
    tok = _token()
    resp = client.post(
        "/rpc/v1/record_event",
        json={
            "event_type": "dispatch_completed",
            "task_id": "t-happy",
            "details": {"outcome": "ok"},
            "context": {"session_id": "s", "user_id": "u"},
        },
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 204
    audit_files = list((tmp_path / "audit").iterdir())
    assert len(audit_files) == 1
    lines = audit_files[0].read_text(encoding="utf-8").splitlines()
    entries = [json.loads(l) for l in lines if l.strip()]
    assert any(e["task_id"] == "t-happy" and e["event_type"] == "dispatch_completed" for e in entries)


# ---------------------------------------------------------------------------
# /rpc/v1/events  (audit F3 fix — reader for record_event writer)
# ---------------------------------------------------------------------------


def test_events_rejects_missing_auth(client: TestClient) -> None:
    resp = client.get("/rpc/v1/events?task_id=t1")
    assert resp.status_code == 401


def test_events_rejects_bad_event_type(client: TestClient) -> None:
    tok = _token()
    resp = client.get(
        "/rpc/v1/events?event_type=totally_invented",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 400


def test_events_rejects_bad_task_id(client: TestClient) -> None:
    """task_id with path-traversal chars -> 400."""
    tok = _token()
    resp = client.get(
        "/rpc/v1/events?task_id=..%2Fetc%2Fpasswd",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 400


def test_events_returns_empty_when_no_logs(client: TestClient) -> None:
    tok = _token()
    resp = client.get(
        "/rpc/v1/events?task_id=never-written",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["data"]["count"] == 0
    assert body["data"]["events"] == []


def test_events_round_trip_writer_reader(client: TestClient) -> None:
    """Write 3 events via record_event, read them back via /events filtered by task_id."""
    tok = _token()
    target = "t-round-trip"
    for et in ("dispatch_created", "lease_acquired", "dispatch_completed"):
        r = client.post(
            "/rpc/v1/record_event",
            json={
                "event_type": et,
                "task_id": target,
                "details": {"k": "v"},
                "context": {"session_id": "s", "user_id": "u"},
            },
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert r.status_code == 204
    # Also write one event for a different task to confirm filter works.
    client.post(
        "/rpc/v1/record_event",
        json={
            "event_type": "dispatch_created",
            "task_id": "other-task",
            "details": {},
            "context": {"session_id": "s", "user_id": "u"},
        },
        headers={"Authorization": f"Bearer {tok}"},
    )

    resp = client.get(
        f"/rpc/v1/events?task_id={target}",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"]["count"] == 3
    types = {e["event_type"] for e in body["data"]["events"]}
    assert types == {"dispatch_created", "lease_acquired", "dispatch_completed"}
    assert all(e["task_id"] == target for e in body["data"]["events"])


def test_events_filter_by_event_type(client: TestClient) -> None:
    tok = _token()
    for et in ("dispatch_created", "dispatch_failed", "dispatch_completed"):
        client.post(
            "/rpc/v1/record_event",
            json={
                "event_type": et,
                "task_id": f"t-{et}",
                "details": {},
                "context": {"session_id": "s", "user_id": "u"},
            },
            headers={"Authorization": f"Bearer {tok}"},
        )
    resp = client.get(
        "/rpc/v1/events?event_type=dispatch_failed",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"]["count"] >= 1
    assert all(e["event_type"] == "dispatch_failed" for e in body["data"]["events"])


# ---------------------------------------------------------------------------
# Review BLOCKER fix (2026-06-10 22:38): a malformed audit-log line with
# deeply-nested JSON raises RecursionError, not JSONDecodeError. The pre-fix
# reader caught only JSONDecodeError and would crash the endpoint with 500.
# ---------------------------------------------------------------------------


def test_events_reader_survives_deeply_nested_audit_line(client: TestClient, tmp_path: Path) -> None:
    """Plant a single audit log line with pathologically nested JSON and
    confirm the reader skips it instead of crashing with RecursionError."""
    from datetime import datetime, timezone
    audit_dir = tmp_path / "audit"
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    log_file = audit_dir / f"audit-{today}.log"

    # 5000 nested arrays — deeper than CPython's default recursion limit.
    nested = "[" * 5000 + "]" * 5000
    log_file.write_text(nested + "\n", encoding="utf-8")
    # Also append one valid line so we can confirm reader continues past the bad one.
    valid = json.dumps({
        "event_type": "dispatch_created",
        "task_id": "t-after-bad-line",
        "details": {},
        "context": {"session_id": "s", "user_id": "u"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    log_file.write_text(nested + "\n" + valid + "\n", encoding="utf-8")

    tok = _token()
    resp = client.get(
        "/rpc/v1/events?task_id=t-after-bad-line",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 200, (
        f"reader must not crash on deeply-nested JSON line; got {resp.status_code}: {resp.text[:200]}"
    )
    body = resp.json()
    # The valid line should be returned (count >= 1), proving the reader
    # didn't bail out on the bad line.
    assert body["data"]["count"] == 1
    assert body["data"]["events"][0]["task_id"] == "t-after-bad-line"
