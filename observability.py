"""
ADR-032: Single task_id observability sink.

A shared SQLite database (path: OBS_DB_PATH env, default
/var/lib/design-e/observability.sqlite) that every dispatch-fabric hop
appends to so an operator can run

    SELECT * FROM task_events WHERE task_id = ? ORDER BY timestamp

and see the full timeline of a dispatch in one query.

Hops: 'design-e' (this repo) and 'consumer' (hermes-agent). zenbrain
stays on PG by design — see ADR-032 §Scope.

Design notes
------------
* Append-only. WAL mode. Per-call connect/close keeps the write surface
  trivially safe under multi-process contention at the rates we expect
  (single-digit TPS; ADR §Residual risk has the contention threshold).
* emit() is best-effort: SQLite failures are logged but never propagate
  to the caller. Observability MUST NOT break the request path.
* Schema migration is idempotent (CREATE TABLE IF NOT EXISTS).
"""
from __future__ import annotations

import json as _json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)

OBS_DB_PATH = Path(os.getenv("OBS_DB_PATH", "/var/lib/design-e/observability.sqlite"))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS task_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id     TEXT    NOT NULL,
  hop         TEXT    NOT NULL,
  event       TEXT    NOT NULL,
  timestamp   TEXT    NOT NULL,
  payload     TEXT,
  CHECK (length(task_id) BETWEEN 1 AND 128)
);
CREATE INDEX IF NOT EXISTS idx_task_events_task_id ON task_events(task_id);
CREATE INDEX IF NOT EXISTS idx_task_events_ts ON task_events(timestamp);
"""

VALID_HOPS = {"design-e", "consumer", "zenbrain"}
VALID_EVENTS = {
    "dispatched",
    "result_read",
    "leased",
    "heartbeat",
    "completed",
    "failed",
    "expired",
    "reaped",
}


def _connect(path: Path | None = None) -> sqlite3.Connection:
    p = path or _resolve_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), timeout=5.0, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(_SCHEMA)
    return conn


def _resolve_path() -> Path:
    # Re-read module attribute each call so tests can monkeypatch OBS_DB_PATH.
    import observability as _self  # type: ignore
    return _self.OBS_DB_PATH


def emit(
    task_id: str,
    hop: str,
    event: str,
    payload: dict[str, Any] | None = None,
) -> None:
    """Append one event to the sink. Best-effort: never raises."""
    try:
        if hop not in VALID_HOPS:
            logger.warning("observability: unknown hop %r (event=%s)", hop, event)
        if event not in VALID_EVENTS:
            logger.warning("observability: unknown event %r (hop=%s)", event, hop)
        ts = datetime.now(timezone.utc).isoformat()
        payload_str = _json.dumps(payload) if payload is not None else None
        conn = _connect()
        try:
            conn.execute(
                "INSERT INTO task_events (task_id, hop, event, timestamp, payload) "
                "VALUES (?, ?, ?, ?, ?)",
                (task_id, hop, event, ts, payload_str),
            )
        finally:
            conn.close()
    except Exception as e:  # pragma: no cover - logged, not raised
        logger.error("observability.emit failed: %s", e)


def tail(task_id: str) -> list[dict[str, Any]]:
    """Return the full event timeline for a task_id (oldest first)."""
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT task_id, hop, event, timestamp, payload "
            "FROM task_events WHERE task_id = ? ORDER BY timestamp ASC, id ASC",
            (task_id,),
        )
        rows = []
        for row in cur.fetchall():
            t, h, e, ts, p = row
            rows.append(
                {
                    "task_id": t,
                    "hop": h,
                    "event": e,
                    "timestamp": ts,
                    "payload": _json.loads(p) if p else None,
                }
            )
        return rows
    finally:
        conn.close()


def _format_row(r: dict[str, Any]) -> str:
    pl = ""
    if r["payload"]:
        pl = " " + _json.dumps(r["payload"], separators=(",", ":"))
    return f"{r['timestamp']}  {r['hop']:>9}  {r['event']:<11}{pl}"


def _main(argv: Iterable[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m observability",
        description="ADR-032 observability sink CLI",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_tail = sub.add_parser("tail", help="Print the timeline for a task_id")
    p_tail.add_argument("task_id")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.cmd == "tail":
        rows = tail(args.task_id)
        if not rows:
            print(f"(no events for task_id={args.task_id})")
            return 1
        print(f"# Timeline for task_id={args.task_id} ({len(rows)} events)")
        for r in rows:
            print(_format_row(r))
        return 0
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
