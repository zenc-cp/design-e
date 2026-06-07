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
