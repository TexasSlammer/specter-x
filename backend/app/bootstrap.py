"""Bootstrap: load org data, ingest datasets, evaluate scenarios, build cases.

Used by app startup (auto-loading the demo so a fresh clone shows a working
SOC in seconds) and by the /api/evaluate endpoint and integration tests.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select, func
from sqlalchemy.orm import Session

from .attack_graph import build, find_reachable_sensitive_resources
from .ingestion import ingest_batch, load_jsonl
from .investigations.cases import correlate
from .models import Alert, Case, Event, Grant, Identity, Resource
from .risk_engine import run_all_detections, score_identity

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASETS = Path(os.environ.get("SPECTER_DATASETS", REPO_ROOT / "datasets"))
DEFAULT_CTX = {"ip": "198.51.100.2", "asn_type": "corporate", "time": "14:00"}


def load_org(db: Session) -> dict:
    """Load identities, resources and grants from datasets/org.json (idempotent by PK)."""
    org = json.loads((DATASETS / "org.json").read_text())
    for i in org["identities"]:
        if db.get(Identity, i["identity_id"]) is None:
            db.add(Identity(id=i["identity_id"], display_name=i["display_name"],
                            kind=i.get("kind", "user"), department=i.get("department", ""),
                            privileged=i.get("privileged", False)))
    for r in org["resources"]:
        if db.get(Resource, r["resource_id"]) is None:
            db.add(Resource(id=r["resource_id"], label=r["label"],
                            kind=r.get("kind", "cloud_resource"),
                            sensitivity=r["sensitivity"]))
    existing = {g.grant_id for g in db.execute(select(Grant)).scalars()}
    for g in org["grants"]:
        if g["grant_id"] not in existing:
            db.add(Grant(grant_id=g["grant_id"], kind=g["kind"], from_id=g["from_id"],
                         to_id=g["to_id"], resource_id=g.get("resource_id"),
                         scopes=g.get("scopes"), conditions=g.get("conditions"),
                         verified=g.get("verified", True)))
    db.commit()
    return org


_GRAPH_CACHE = None


def org_graph(db: Session | None = None):
    """Build (once) the attack graph from org.json — dict form carries the
    resource metadata + scope_resources mapping that ORM rows lack."""
    global _GRAPH_CACHE
    if _GRAPH_CACHE is None:
        org = json.loads((DATASETS / "org.json").read_text())
        _GRAPH_CACHE = build(org)
    return _GRAPH_CACHE


def events_as_dicts(db: Session, identity_ids: list[str] | None = None) -> list[dict]:
    q = select(Event).order_by(Event.timestamp, Event.event_id)
    if identity_ids:
        q = q.where(Event.identity_id.in_(identity_ids))
    out = []
    for e in q.scalars():
        out.append({"event_id": e.event_id, "source": e.source, "type": e.type,
                    "timestamp": e.timestamp.isoformat().replace("+00:00", "Z"),
                    "identity_id": e.identity_id,
                    "attributes": e.attributes or {}, "raw": e.raw or {}})
    return out


def detection_ctx(db: Session, org: dict) -> dict:
    idents = {i.id: {"privileged": i.privileged, "kind": i.kind, "display_name": i.display_name}
              for i in db.execute(select(Identity)).scalars()}
    groups = org.get("groups", {})
    privileged_groups = [gid for gid in groups if gid == "grp-it-admins"]
    return {"identities": idents, "cities": org.get("cities", {}),
            "privileged_groups": privileged_groups}


def evaluate_scenario(db: Session, scenario: str, org: dict | None = None) -> dict:
    """Ingest a scenario file (idempotent), run detections, persist alerts + case(s)."""
    org = org or load_org(db)
    gt = json.loads((DATASETS / "ground_truth.json").read_text())
    meta = gt["attack_scenarios"][scenario]
    events = load_jsonl(DATASETS / meta["events_file"])
    stats = ingest_batch(db, events)

    ctx = detection_ctx(db, org)
    alerts = run_all_detections(events, ctx)
    _persist_alerts(db, alerts)
    cases = _persist_cases(db, alerts, events, ctx["identities"])

    scores = {}
    graph = org_graph(db)
    for ident in meta["compromised"]:
        id_alerts = [a for a in alerts if a["identity_id"] == ident]
        reach = find_reachable_sensitive_resources(graph, ident, DEFAULT_CTX)
        info = ctx["identities"].get(ident, {})
        scores[ident] = score_identity(ident, id_alerts, {
            "reachable_sensitive": [r["resource_id"] for r in reach],
            "privileged": info.get("privileged", False),
            "directory_role": info.get("privileged", False),
        })
    return {"scenario": scenario, "ingestion": stats, "alerts": alerts,
            "cases": cases, "scores": scores,
            "expected": meta["expected_detections"]}


def _alert_fingerprint(detection_id: str, identity_id: str, event_refs: list[str]) -> str:
    """Deterministic alert id: the same detection firing on the same evidence
    IS the same alert, so re-running a scenario must reproduce its id instead
    of minting a fresh random one. This makes /api/evaluate idempotent end to
    end — events by event_id, alerts by content fingerprint, cases by
    identity (see cases.correlate)."""
    payload = f"{detection_id}|{identity_id}|{','.join(sorted(event_refs))}"
    return "alr-" + hashlib.sha256(payload.encode()).hexdigest()[:12]


def _persist_alerts(db: Session, alerts: list[dict]) -> None:
    for a in alerts:
        aid = a.get("alert_id") or _alert_fingerprint(
            a["detection_id"], a["identity_id"], a.get("event_refs", []))
        a["alert_id"] = aid
        if db.get(Alert, aid) is None:
            db.add(Alert(alert_id=aid, detection_id=a["detection_id"],
                         severity=a["severity"], confidence=a["confidence"],
                         identity_id=a["identity_id"], reason=a["reason"],
                         event_refs=a.get("event_refs", []),
                         false_positive_notes=a.get("false_positive_notes", ""),
                         created_at=datetime.now(timezone.utc)))
    db.commit()


def _persist_cases(db: Session, alerts: list[dict], events: list[dict],
                   identities_meta: dict) -> list[dict]:
    built = correlate(alerts, events, identities_meta)
    for c in built:
        if db.get(Case, c["case_id"]) is None:
            db.add(Case(case_id=c["case_id"], title=c["title"], severity=c["severity"],
                        identity_id=c["identity_id"], status="open",
                        conclusion=c["conclusion"],
                        created_at=datetime.now(timezone.utc)))
            for a in alerts:
                if a["identity_id"] == c["identity_id"] and a.get("alert_id"):
                    row = db.get(Alert, a["alert_id"])
                    if row is not None and row.case_id is None:
                        row.case_id = c["case_id"]
    db.commit()
    return built


def ensure_demo_data() -> None:
    """Startup hook: on an empty database, load org + datasets and evaluate all scenarios."""
    from .models import engine, SessionLocal
    from .models import init_db
    init_db()
    if os.environ.get("SPECTER_AUTOLOAD", "1") == "0":
        return
    with SessionLocal() as db:
        n = db.execute(select(func.count()).select_from(Identity)).scalar_one()
        if n > 0:
            return
        org = load_org(db)
        gt = json.loads((DATASETS / "ground_truth.json").read_text())
        ingest_batch(db, load_jsonl(DATASETS / gt["normal_baseline"]["events_file"]))
        for name in gt["attack_scenarios"]:
            evaluate_scenario(db, name, org)
