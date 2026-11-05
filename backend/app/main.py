"""SPECTER X API + static dashboard. Run: uvicorn app.main:app --reload"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from .attack_graph import build, find_reachable_sensitive_resources
from .auth import check_token, require_admin
from .bootstrap import (DATASETS, DEFAULT_CTX, ensure_demo_data, evaluate_scenario,
                        load_jsonl, load_org, org_graph, detection_ctx)
from .ingestion import ingest_batch
from .investigations.cases import correlate
from .models import Alert, Case, Event, Grant, Identity, ResponseAudit, Resource, SessionLocal
from .response import actions
from .risk_engine import run_all_detections, score_identity

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ensure_demo_data()  # first boot loads the Northstar Health demo automatically
    yield


app = FastAPI(title="SPECTER X", version="1.0.0",
              description="Cloud identity attack-path analysis & autonomous investigation (demo)",
              lifespan=lifespan)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ------------------------------------------------------------------ ingest
class IngestBody(BaseModel):
    events: list[Any]  # malformed items are REJECTED by the validator, not by schema (CONTRACTS §1)


@app.post("/api/ingest")
def ingest(body: IngestBody, db: Session = Depends(get_db),
           pair: tuple[str, str] = Depends(check_token)):
    return ingest_batch(db, body.events)


# -------------------------------------------------------------- identities
@app.get("/api/identities")
def list_identities(db: Session = Depends(get_db),
                    pair: tuple[str, str] = Depends(check_token)):
    org = load_org(db)
    ctx = detection_ctx(db, org)
    graph = org_graph(db)
    alerts = _all_alerts(db)
    out = []
    for i in db.execute(select(Identity)).scalars():
        id_alerts = [a for a in alerts if a["identity_id"] == i.id]
        reach = find_reachable_sensitive_resources(graph, i.id, DEFAULT_CTX)
        score = score_identity(i.id, id_alerts, {
            "reachable_sensitive": [r["resource_id"] for r in reach],
            "privileged": i.privileged, "directory_role": i.privileged,
        })
        out.append({"identity_id": i.id, "display_name": i.display_name, "kind": i.kind,
                    "department": i.department, "privileged": i.privileged,
                    "score": score["score"], "severity_band": score["severity_band"]})
    out.sort(key=lambda x: -x["score"])
    return out


@app.get("/api/identities/{identity_id}")
def identity_detail(identity_id: str, db: Session = Depends(get_db),
                    pair: tuple[str, str] = Depends(check_token)):
    ident = db.get(Identity, identity_id)
    if ident is None:
        raise HTTPException(404, "identity not found")
    org = load_org(db)
    ctx = detection_ctx(db, org)
    graph = org_graph(db)
    alerts = [a for a in _all_alerts(db) if a["identity_id"] == identity_id]
    reach = find_reachable_sensitive_resources(graph, identity_id, DEFAULT_CTX)
    score = score_identity(identity_id, alerts, {
        "reachable_sensitive": [r["resource_id"] for r in reach],
        "privileged": ident.privileged, "directory_role": ident.privileged,
    })
    consents = db.execute(select(Grant.to_id, Grant.scopes).where(
        Grant.kind == "APP_CONSENT", Grant.from_id == identity_id)).all()
    labels = {r.id: r.label for r in db.execute(select(Resource)).scalars()}
    return {
        "identity": {"identity_id": ident.id, "display_name": ident.display_name,
                     "kind": ident.kind, "department": ident.department,
                     "privileged": ident.privileged, "active": ident.active,
                     "score": score["score"], "severity_band": score["severity_band"]},
        # flat score for simple clients; risk/score_breakdown/components for normalizers
        "score": score["score"], "severity_band": score["severity_band"],
        "risk": score, "score_breakdown": score, "components": score["components"],
        "alerts": alerts,
        "reachable_sensitive_resources": [
            {"resource_id": r["resource_id"], "label": labels.get(r["resource_id"], r["resource_id"]),
             "sensitivity": "sensitive", "via": r.get("via", ""), "paths": r.get("paths", [])}
            for r in reach],
        "consented_apps": [{"app_id": app_id, "scopes": scopes or []} for app_id, scopes in consents],
        "_ctx_note": "reachability evaluated with corporate default context",
    }


# ------------------------------------------------------------------ alerts
@app.get("/api/alerts")
def list_alerts(severity: str | None = None, limit: int = 100, offset: int = 0,
                db: Session = Depends(get_db), pair: tuple[str, str] = Depends(check_token)):
    q = select(Alert).order_by(Alert.created_at.desc())
    if severity:
        q = q.where(Alert.severity == severity)
    rows = db.execute(q.offset(offset).limit(limit)).scalars().all()
    return [{"alert_id": a.alert_id, "detection_id": a.detection_id, "severity": a.severity,
             "confidence": a.confidence, "identity_id": a.identity_id, "reason": a.reason,
             "event_refs": a.event_refs, "case_id": a.case_id,
             "created_at": a.created_at.isoformat()} for a in rows]


# ------------------------------------------------------------------- cases
@app.get("/api/cases")
def list_cases(db: Session = Depends(get_db), pair: tuple[str, str] = Depends(check_token)):
    rows = db.execute(select(Case)).scalars().all()
    alerts = _all_alerts(db)
    return [{"case_id": c.case_id, "title": c.title, "severity": c.severity,
             "identity_id": c.identity_id, "status": c.status,
             "alert_count": sum(1 for a in alerts if a.get("case_id") == c.case_id),
             "created_at": c.created_at.isoformat()} for c in rows]


@app.get("/api/cases/{case_id}")
def case_detail(case_id: str, db: Session = Depends(get_db),
                pair: tuple[str, str] = Depends(check_token)):
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(404, "case not found")
    alerts = [a for a in _all_alerts(db) if a.get("case_id") == case_id]
    ident_events = _events_for(db, [case.identity_id])
    built = correlate(alerts, ident_events, {case.identity_id: {"display_name": case.title}})
    timeline = built[0]["timeline"] if built else []
    return {"case_id": case.case_id, "title": case.title, "severity": case.severity,
            "identity_id": case.identity_id, "status": case.status,
            "conclusion": case.conclusion, "alerts": alerts, "timeline": timeline,
            "created_at": case.created_at.isoformat()}


# ------------------------------------------------------------------- graph
@app.get("/api/graph")
def graph(identity_id: str, db: Session = Depends(get_db),
          pair: tuple[str, str] = Depends(check_token)):
    if db.get(Identity, identity_id) is None:
        raise HTTPException(404, "identity not found")
    g = org_graph(db)
    reach = find_reachable_sensitive_resources(g, identity_id, DEFAULT_CTX)
    on_path_grants = {gid for r in reach for path in r.get("paths", []) for gid in path}

    keep = {identity_id}
    # walk OUT from the identity (attack direction): groups it belongs to,
    # roles, consented apps — then resources those grantors can reach
    frontier = [identity_id]
    for _ in range(3):
        nxt: set[str] = set()
        for node in frontier:
            for succ in g.successors(node):
                if succ not in keep:
                    nxt.add(succ)
        keep |= nxt
        frontier = list(nxt)
    for r in reach:
        keep.add(r["resource_id"])

    nodes, edges = [], []
    for n, data in g.nodes(data=True):
        if n in keep:
            nodes.append({"id": n, "label": data.get("label", n),
                          "kind": data.get("kind", "user"),
                          "privileged": bool(data.get("privileged", False)),
                          "sensitive": bool(data.get("sensitive", False))})
    for u, v, data in g.edges(data=True):
        if u in keep and v in keep:
            edges.append({"from": u, "to": v, "kind": data.get("kind", ""),
                          "grant_id": data.get("grant_id", ""),
                          "on_path": data.get("grant_id", "") in on_path_grants})
    return {"nodes": nodes, "edges": edges,
            "reachable": [{"resource_id": r["resource_id"], "via": r.get("via", "")} for r in reach]}


# ---------------------------------------------------------------- evaluate
class EvaluateBody(BaseModel):
    scenario: str


@app.post("/api/evaluate")
def evaluate(body: EvaluateBody, db: Session = Depends(get_db),
             pair: tuple[str, str] = Depends(check_token)):
    gt = json.loads((DATASETS / "ground_truth.json").read_text())
    if body.scenario not in gt["attack_scenarios"]:
        raise HTTPException(404, f"unknown scenario '{body.scenario}'")
    return evaluate_scenario(db, body.scenario)


# ---------------------------------------------------------------- response
class RespondBody(BaseModel):
    identity_id: str = ""
    app_id: str = ""
    confirm: bool = True


def _respond(action: str, body: RespondBody, db: Session, token: str):
    if not body.confirm:
        raise HTTPException(400, "confirm=true required")
    if action == "consent_revoke":
        result = actions.consent_revoke(db, body.identity_id, body.app_id or None, "admin")
    elif action == "account_disable":
        result = actions.account_disable(db, body.identity_id, "admin")
    elif action == "session_revoke":
        result = actions.session_revoke(db, body.identity_id, "admin")
    else:
        raise HTTPException(404, "unknown action")
    return result


@app.post("/api/respond/consent_revoke")
def respond_consent(body: RespondBody, db: Session = Depends(get_db),
                    token: str = Depends(require_admin)):
    return _respond("consent_revoke", body, db, token)


@app.post("/api/respond/account_disable")
def respond_disable(body: RespondBody, db: Session = Depends(get_db),
                    token: str = Depends(require_admin)):
    return _respond("account_disable", body, db, token)


@app.post("/api/respond/session_revoke")
def respond_sessions(body: RespondBody, db: Session = Depends(get_db),
                     token: str = Depends(require_admin)):
    return _respond("session_revoke", body, db, token)


# ----------------------------------------------------------------- helpers
def _all_alerts(db: Session) -> list[dict]:
    rows = db.execute(select(Alert)).scalars().all()
    return [{"alert_id": a.alert_id, "detection_id": a.detection_id, "severity": a.severity,
             "confidence": a.confidence, "identity_id": a.identity_id, "reason": a.reason,
             "event_refs": a.event_refs, "case_id": a.case_id,
             "created_at": a.created_at.isoformat()} for a in rows]


def _events_for(db: Session, identity_ids: list[str]) -> list[dict]:
    rows = db.execute(select(Event).where(Event.identity_id.in_(identity_ids))
                      .order_by(Event.timestamp)).scalars().all()
    return [{"event_id": e.event_id, "source": e.source, "type": e.type,
             "timestamp": e.timestamp.isoformat().replace("+00:00", "Z"),
             "identity_id": e.identity_id, "attributes": e.attributes or {},
             "raw": e.raw or {}} for e in rows]


# ----------------------------------------------------------------- static
@app.get("/healthz")
def healthz():
    return {"ok": True}


app.mount("/", StaticFiles(directory=str(FRONTEND), html=True), name="frontend")
