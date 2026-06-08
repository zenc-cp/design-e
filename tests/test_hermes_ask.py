"""
Tests for design_e_endpoint.hermes_ask wired to FoundryHttpTransport (ADR-F).

The transport seam (`HermesTransport` + module-level `_transport`) lets us inject
a `FakeHermesTransport` to drive the route end-to-end without touching the
network. Covers happy-path, timeout, and transport-error.

ADR: session-state/d2ed4d4e-.../files/adr-design-e-hermes-wiring-F.md
Issue: zenc-cp/design-e#2
"""
from __future__ import annotations

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient

import design_e_endpoint as dee


def _token(secret: str = "test-secret") -> str:
    return jwt.encode(
        {
            "sub": "scout",
            "aud": "https://zenops-cloud-dispatch",
            "tid": "test-tenant-id",
            "iss": "https://login.microsoftonline.com/test-tenant-id/v2.0",
        },
        secret,
        algorithm="HS256",
    )


class FakeHermesTransport:
    """In-process transport: records calls, returns a canned answer or raises."""

    def __init__(self, *, answer: str | None = None, exc: Exception | None = None) -> None:
        self._answer = answer
        self._exc = exc
        self.calls: list[tuple[str, str]] = []

    async def complete(self, query: str, *, model: str) -> str:
        self.calls.append((query, model))
        if self._exc is not None:
            raise self._exc
        assert self._answer is not None
        return self._answer


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    # Reset the module-level transport singleton so each test gets a clean slate.
    monkeypatch.setattr(dee, "_transport", None, raising=False)
    return TestClient(dee.app)


def test_hermes_ask_happy_path_returns_llm_answer(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    fake = FakeHermesTransport(answer="PONG-from-llm")
    monkeypatch.setattr(dee, "_transport", fake, raising=False)

    resp = client.post(
        "/rpc/v1/hermes_ask",
        json={"query": "ping", "context": {"session_id": "s1", "user_id": "u1"}},
        headers={"Authorization": f"Bearer {_token()}"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["data"]["answer"] == "PONG-from-llm"
    assert body["data"]["confidence"] == 1.0
    assert body["data"]["sources"] == []
    assert "trace_id" in body["data"]
    assert fake.calls and fake.calls[0][0] == "ping"


def test_hermes_ask_timeout_returns_503(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    fake = FakeHermesTransport(exc=httpx.TimeoutException("timeout"))
    monkeypatch.setattr(dee, "_transport", fake, raising=False)

    resp = client.post(
        "/rpc/v1/hermes_ask",
        json={"query": "ping", "context": {"session_id": "s1", "user_id": "u1"}},
        headers={"Authorization": f"Bearer {_token()}"},
    )

    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "error"
    assert body["error"]["code"] == "SERVICE_UNAVAILABLE"


def test_hermes_ask_transport_error_returns_503(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    fake = FakeHermesTransport(exc=httpx.TransportError("conn refused"))
    monkeypatch.setattr(dee, "_transport", fake, raising=False)

    resp = client.post(
        "/rpc/v1/hermes_ask",
        json={"query": "ping", "context": {"session_id": "s1", "user_id": "u1"}},
        headers={"Authorization": f"Bearer {_token()}"},
    )

    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "error"
    assert body["error"]["code"] == "SERVICE_UNAVAILABLE"
