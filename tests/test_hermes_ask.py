"""
Tests for design_e_endpoint.hermes_ask wired to FoundryHttpTransport (ADR-F).

SKELETON committed pre-Aider to avoid Aider's 0-byte-new-file failure mode
(see orch-dispatch SKILL.md, anti-pattern gate row 1). Aider will FILL these
3 tests + the supporting FakeHermesTransport. Skeleton imports are intentionally
minimal so the file is non-empty but does not yet collect-as-pass.

ADR: session-state/d2ed4d4e-.../files/adr-design-e-hermes-wiring-F.md
Issue: zenc-cp/design-e#2
"""
from __future__ import annotations

import pytest

# Aider: implement the three tests below per ADR-F spec.
# All three must use FastAPI TestClient + a FakeHermesTransport injected
# via design_e_endpoint._transport, or respx for outbound httpx mocking.


@pytest.mark.skip(reason="Aider to implement per ADR-F")
def test_hermes_ask_happy_path_returns_llm_answer() -> None:
    """Happy path: transport.complete returns 'PONG'; response.data.answer == 'PONG'; status 200."""
    raise NotImplementedError


@pytest.mark.skip(reason="Aider to implement per ADR-F")
def test_hermes_ask_timeout_returns_503() -> None:
    """httpx.TimeoutException from transport -> HTTP 503 with error.code == 'SERVICE_UNAVAILABLE'."""
    raise NotImplementedError


@pytest.mark.skip(reason="Aider to implement per ADR-F")
def test_hermes_ask_transport_error_returns_503() -> None:
    """httpx.TransportError from transport -> HTTP 503 with error.code == 'SERVICE_UNAVAILABLE'."""
    raise NotImplementedError
