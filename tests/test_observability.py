"""
ADR-032 observability sink tests.

Covers:
- emit() inserts a row with the right shape
- emit() is best-effort: bad path does not raise
- tail() returns oldest-first
- design-e dispatch emits 'dispatched' to the sink
- design-e get_results 200 emits 'result_read' to the sink
- tail CLI prints the timeline and exits 0
"""
from __future__ import annotations

import json
import sqlite3
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import jwt
import pytest
from fastapi.testclient import TestClient

import design_e_endpoint as dee
import observability


@pytest.fixture
def obs_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    p = tmp_path / "obs.sqlite"
    monkeypatch.setattr(observability, "OBS_DB_PATH", p, raising=False)
    return p


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


def test_emit_inserts_row(obs_db: Path) -> None:
    observability.emit("t-1", "design-e", "dispatched", {"specialist": "Scout"})
    with sqlite3.connect(str(obs_db)) as c:
        rows = c.execute(
            "SELECT task_id, hop, event, payload FROM task_events"
        ).fetchall()
    assert len(rows) == 1
    t, h, e, p = rows[0]
    assert (t, h, e) == ("t-1", "design-e", "dispatched")
    assert json.loads(p) == {"specialist": "Scout"}


def test_emit_is_best_effort_on_bad_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Point at a file inside a path that cannot be created (a regular file
    # used as if it were a directory)
    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir")
    bad = blocker / "obs.sqlite"
    monkeypatch.setattr(observability, "OBS_DB_PATH", bad, raising=False)
    # Must NOT raise
    observability.emit("t-2", "design-e", "dispatched")


def test_tail_returns_oldest_first(obs_db: Path) -> None:
    observability.emit("t-3", "design-e", "dispatched")
    observability.emit("t-3", "consumer", "leased")
    observability.emit("t-3", "consumer", "completed")
    timeline = observability.tail("t-3")
    assert [r["event"] for r in timeline] == ["dispatched", "leased", "completed"]
    assert all(r["task_id"] == "t-3" for r in timeline)


def test_tail_empty_for_unknown_task(obs_db: Path) -> None:
    assert observability.tail("never-seen") == []


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
    return TestClient(dee.app)


def test_dispatch_emits_dispatched_event(
    client: TestClient, obs_db: Path
) -> None:
    tok = _make_token()
    resp = client.post(
        "/rpc/v1/dispatch_specialist",
        headers={"Authorization": f"Bearer {tok}"},
        json={
            "specialist": "Scout",
            "task": {"role": "analyst", "payload": {"q": "hi"}, "ttl_sec": 30},
            "context": {"trace_id": "tr-1", "user_id": "u-1", "session_id": "s-1"},
        },
    )
    assert resp.status_code == 202, resp.text
    task_id = resp.json()["data"]["task_id"]
    timeline = observability.tail(task_id)
    assert len(timeline) == 1
    assert timeline[0]["hop"] == "design-e"
    assert timeline[0]["event"] == "dispatched"
    assert timeline[0]["payload"]["specialist"] == "Scout"
    assert timeline[0]["payload"]["ttl_sec"] == 30


def test_get_results_emits_result_read_event(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, obs_db: Path
) -> None:
    results_dir = tmp_path / "results"
    task_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
    (results_dir / f"{task_id}.json").write_text(
        json.dumps({"task_id": task_id, "status": "completed"}),
        encoding="utf-8",
    )
    tok = _make_token()
    resp = client.get(
        f"/rpc/v1/results/{task_id}",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 200
    timeline = observability.tail(task_id)
    assert len(timeline) == 1
    assert timeline[0]["event"] == "result_read"
    assert timeline[0]["hop"] == "design-e"


def test_tail_cli_prints_timeline_and_exits_zero(obs_db: Path, capsys: pytest.CaptureFixture[str]) -> None:
    observability.emit("cli-1", "design-e", "dispatched")
    rc = observability._main(["tail", "cli-1"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "cli-1" in out
    assert "dispatched" in out


def test_tail_cli_returns_1_for_unknown_task(obs_db: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = observability._main(["tail", "missing"])
    assert rc == 1
    assert "no events" in capsys.readouterr().out
