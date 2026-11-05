"""Event ingestion: validation, canonicalization, idempotent storage.

Contract: CONTRACTS §1. Replay safety is a first-class feature — pushing the
same batch twice yields `duplicates` counts and ZERO extra rows (enforced by
the event_id primary key and verified by integration tests).
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Event

SOURCES = {"entra", "cloudtrail", "oauth"}
TYPES = {"signin", "signinfailure", "mfa_denied", "consent_granted",
         "role_assigned", "api_call", "session_revoked", "account_disabled"}
REQUIRED = ("event_id", "source", "type", "timestamp", "identity_id")


class Rejected(ValueError):
    """A structurally invalid event. message carries the validator reason."""


def parse_ts(raw: str) -> datetime:
    dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def validate(e: dict) -> dict:
    if not isinstance(e, dict):
        raise Rejected("event must be an object")
    for field in REQUIRED:
        if not e.get(field):
            raise Rejected(f"missing required field '{field}'")
    if e["source"] not in SOURCES:
        raise Rejected(f"unknown source '{e['source']}'")
    if e["type"] not in TYPES:
        raise Rejected(f"unknown type '{e['type']}'")
    try:
        parse_ts(e["timestamp"])
    except Exception as exc:  # noqa: BLE001 - validator boundary
        raise Rejected(f"bad timestamp: {exc}") from exc
    if not isinstance(e.get("attributes", {}), dict):
        raise Rejected("attributes must be an object")
    return e


def ingest_batch(db: Session, events: list[dict]) -> dict:
    """Returns {accepted, duplicates, rejected[]} — never raises for bad events."""
    accepted = duplicates = 0
    rejected: list[dict] = []
    for raw in events:
        try:
            e = validate(raw)
        except Rejected as exc:
            rejected.append({"event_id": (raw or {}).get("event_id", "?") if isinstance(raw, dict) else "?",
                             "error": str(exc)})
            continue
        exists = db.get(Event, e["event_id"]) is not None
        if exists:
            duplicates += 1
            continue
        db.add(Event(
            event_id=e["event_id"], source=e["source"], type=e["type"],
            timestamp=parse_ts(e["timestamp"]), identity_id=e["identity_id"],
            attributes=e.get("attributes", {}), raw=e.get("raw", {}),
        ))
        accepted += 1
    db.commit()
    return {"accepted": accepted, "duplicates": duplicates, "rejected": rejected}


def load_jsonl(path) -> list[dict]:
    import json
    out = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out
