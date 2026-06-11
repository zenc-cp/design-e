"""
ADR-025 implementation tests 7–9: GET /rpc/v1/results/{task_id}

RED-FIRST: these all fail until the route is added in S4.
"""
from __future__ import annotations

import json
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient

import design_e_endpoint as dee


def _make_token(secret: str = "test-secret", aud: str = "https://zenops-cloud-dispatch") -> str:
    return jwt.encode(
        {
            "sub": "scout",
            "aud": aud,
            "tid": "test-tenant-id",
            "iss": "https://login.microsoftonline.com/test-tenant-id/v2.0",
        },
        secret,
        algorithm="HS256",
    )


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    # The route reads RESULTS_PATH at request time.
    monkeypatch.setattr(dee, "RESULTS_PATH", results_dir, raising=False)
    return TestClient(dee.app)


def test_results_rpc_returns_404_when_missing(client: TestClient) -> None:
    """Test 7 — missing task returns 404."""
    tok = _make_token()
    resp = client.get(
        "/rpc/v1/results/nonexistent-task-id",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 404


def test_results_rpc_returns_200_when_present(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test 8 — present task returns 200 + JSON body."""
    results_dir = tmp_path / "results"
    payload = {
        "task_id": "abc",
        "specialist": "Scout",
        "status": "completed",
        "output": {"findings": ["nothing of note"]},
        "started_at": "2026-06-07T15:00:00Z",
        "finished_at": "2026-06-07T15:00:05Z",
        "latency_ms": 5000,
        "model": "gpt-5-chat",
        "tool_calls": 0,
    }
    (results_dir / "abc.json").write_text(json.dumps(payload), encoding="utf-8")

    tok = _make_token()
    resp = client.get(
        "/rpc/v1/results/abc",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 200
    assert resp.json() == payload


def test_results_rpc_rejects_unauthenticated(client: TestClient) -> None:
    """Test 9 — missing/invalid auth returns 401."""
    resp = client.get("/rpc/v1/results/any-task-id")
    assert resp.status_code == 401


def test_results_rpc_rejects_path_traversal_dotdot(client: TestClient) -> None:
    """Path traversal with .. — must reject with 400."""
    tok = _make_token()
    resp = client.get(
        "/rpc/v1/results/..%2Fetc%2Fpasswd",
        headers={"Authorization": f"Bearer {tok}"},
    )
    # Either 400 or 404 (route not match) is acceptable, just NOT 500 or 200
    assert resp.status_code in (400, 404, 422)


def test_results_rpc_rejects_invalid_task_id_chars(client: TestClient) -> None:
    """Invalid chars (spaces) in task_id — must reject with 400."""
    tok = _make_token()
    resp = client.get(
        "/rpc/v1/results/has%20spaces",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data["status"] == "error"
    assert "BAD_REQUEST" in data["error"]["code"]


def test_results_rpc_rejects_too_long_task_id(client: TestClient) -> None:
    """Task_id exceeding 128 chars — must reject with 400."""
    tok = _make_token()
    long_task_id = "a" * 129
    resp = client.get(
        f"/rpc/v1/results/{long_task_id}",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data["status"] == "error"
    assert "BAD_REQUEST" in data["error"]["code"]


def test_results_rpc_accepts_uuid_task_id(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """UUID-format task_id with corresponding file — must return 200."""
    results_dir = tmp_path / "results"
    task_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
    payload = {
        "task_id": task_id,
        "specialist": "Scout",
        "status": "completed",
        "output": {"result": "ok"},
    }
    (results_dir / f"{task_id}.json").write_text(json.dumps(payload), encoding="utf-8")
    
    tok = _make_token()
    resp = client.get(
        f"/rpc/v1/results/{task_id}",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 200
    assert resp.json() == payload


# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Audit follow-ups (design-e#8 F9, design-e#9 F10) -- defense-in-depth
# ---------------------------------------------------------------------------


def test_results_rpc_malformed_task_id_without_auth_returns_401(client: TestClient) -> None:
    """F9 / design-e#8: unauthenticated callers must get 401 regardless of
    task_id shape, so attackers cannot distinguish well-formed from malformed
    task_ids before auth."""
    resp = client.get("/rpc/v1/results/has spaces")
    assert resp.status_code == 401


def test_results_rpc_500_does_not_leak_exception_text(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F10 / design-e#9: a 500 must NOT echo str(exception) -- sensitive
    detail (paths, IPs, partial secrets) must stay server-side."""
    def boom(*_a, **_kw):
        raise RuntimeError("secret-value /etc/shadow 10.0.0.7")

    monkeypatch.setattr(dee, "validate_entra_token", boom)
    tok = _make_token()
    resp = client.get(
        "/rpc/v1/results/valid-task-id",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 500
    body = resp.text
    assert "secret-value" not in body
    assert "/etc/shadow" not in body
    assert "10.0.0.7" not in body
    data = resp.json()
    assert data["error"]["message"] == "internal_error"