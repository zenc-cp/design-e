# design-e

Thin RPC gateway in front of Hermes for ZenOps `dispatch_specialist` and results retrieval.

## What this is

The HTTP entrypoint that ZenOps callers use to enqueue work for Hermes specialist personas and to retrieve results. Validates Entra JWTs, writes dispatches into `/var/lib/design-e/brain-inbox/`, and exposes a `GET /rpc/v1/results/{task_id}` endpoint backed by L2 status files at `/var/lib/design-e/results/`.

## What this isn't

- Not the Hermes agent itself (that lives in [hermes-agent](https://github.com/zenc-cp/hermes-agent)).
- Not the persona/consumer (also in hermes-agent under `agent/specialists/`).
- Not the deploy/systemd surface (that lives in [zenbrain](https://github.com/zenc-cp/zenbrain) under `deploy/`).

## Anchors

- [ADR-025 ZenOps specialists are personas of one Hermes](https://github.com/zenc-cp/zenbrain/blob/main/docs/adr/ADR-025-zenops-specialist-abstraction.md)
- [ADR-025 implementation plan](https://github.com/zenc-cp/zenbrain/blob/main/docs/superpowers/plans/2026-06-07-adr-025-implementation.md)

## Development

```bash
pip install -e .[dev]
pytest
```

## Provenance

Initial commit vendored from `Scratchpad/design_e_endpoint.py` on 2026-06-07. Prior to this commit the file lived only on local disk + the deployed VM with no version control. See plan `§3.5.1` for the home-decision rationale.
