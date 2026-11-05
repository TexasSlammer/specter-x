"""Integration tests: API authz matrix, idempotent ingestion, evaluation flow,
traceability, graph shape. Every acceptance claim in the README traces here.
"""
from __future__ import annotations

import json

from sqlalchemy import func, select

from conftest import ADMIN, ANALYST, REPO

from app.ingestion import load_jsonl


def test_healthz_no_auth(client):
    assert client.get("/healthz").status_code == 200


def test_missing_token_401(client):
    assert client.get("/api/identities").status_code == 401


def test_unknown_token_401(client):
    assert client.get("/api/identities", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_analyst_can_read(client):
    r = client.get("/api/identities", headers=ANALYST)
    assert r.status_code == 200
    assert isinstance(r.json(), list) and len(r.json()) >= 25


def test_analyst_cannot_respond_403(client):
    r = client.post("/api/respond/account_disable",
                    json={"identity_id": "usr-clin.01", "confirm": True}, headers=ANALYST)
    assert r.status_code == 403
    # and nothing happened: identity still active
    from app.models import Identity, SessionLocal
    with SessionLocal() as db:
        assert db.get(Identity, "usr-clin.01").active is True


def test_admin_respond_simulated(client):
    r = client.post("/api/respond/account_disable",
                    json={"identity_id": "usr-clin.02", "confirm": True}, headers=ADMIN)
    assert r.status_code == 200
    body = r.json()
    assert body["simulated"] is True and body["audit_id"].startswith("aud-")
    from app.models import Identity, ResponseAudit, SessionLocal
    with SessionLocal() as db:
        assert db.get(Identity, "usr-clin.02").active is False
        rows = db.execute(select(ResponseAudit).where(
            ResponseAudit.target_id == "usr-clin.02",
            ResponseAudit.action == "account_disable")).scalars().all()
        assert len(rows) == 1 and rows[0].actor_role == "admin"


def test_ingest_replay_is_idempotent(client):
    events = load_jsonl(REPO / "datasets" / "normal" / "baseline.jsonl")
    r1 = client.post("/api/ingest", json={"events": events}, headers=ANALYST).json()
    assert r1["rejected"] == []
    r2 = client.post("/api/ingest", json={"events": events}, headers=ANALYST).json()
    assert r2["accepted"] == 0 and r2["duplicates"] == len(events), "replay must not double-count"
    from app.models import Event, SessionLocal
    with SessionLocal() as db:
        stored = db.execute(select(func.count()).select_from(Event).where(
            Event.event_id.in_([e["event_id"] for e in events]))).scalar_one()
    assert stored == len(events), "exactly one row per event_id regardless of replay count"


def test_malformed_events_rejected(client):
    bad = [
        {"event_id": "evt-x1", "source": "twitter", "type": "signin",
         "timestamp": "2026-11-02T10:00:00Z", "identity_id": "usr-clin.01"},
        {"event_id": "evt-x2", "source": "entra", "type": "signin",
         "identity_id": "usr-clin.01"},
        {"event_id": "evt-x3", "source": "entra", "type": "signin",
         "timestamp": "not-a-time", "identity_id": "usr-clin.01"},
        "not-even-an-object",
    ]
    good = [{"event_id": "evt-ok1", "source": "entra", "type": "signin",
             "timestamp": "2026-11-02T10:00:00Z", "identity_id": "usr-clin.01",
             "attributes": {}}]
    r = client.post("/api/ingest", json={"events": bad + good}, headers=ANALYST).json()
    assert r["accepted"] == 1
    assert {x["event_id"] for x in r["rejected"]} == {"evt-x1", "evt-x2", "evt-x3", "?"}


def test_evaluate_mfa_scenario(client):
    r = client.post("/api/evaluate", json={"scenario": "mfa_fatigue"}, headers=ANALYST)
    assert r.status_code == 200
    body = r.json()
    detected = {a["detection_id"] for a in body["alerts"]}
    assert set(body["expected"]) <= detected, f"missing {set(body['expected']) - detected}"
    # score acceptance from ground truth
    dana = body["scores"]["usr-billing.reyes"]
    assert dana["score"] >= 85 and dana["severity_band"] == "critical"
    # case exists for the compromised identity
    assert any(c["identity_id"] == "usr-billing.reyes" for c in body["cases"])
    # 100% traceability: every event_ref exists in the event store
    from app.models import Event, SessionLocal
    with SessionLocal() as db:
        all_ids = set(db.execute(select(Event.event_id)).scalars())
    for a in body["alerts"]:
        assert a["event_refs"], "alerts must reference events"
        assert set(a["event_refs"]) <= all_ids


def test_identity_detail_after_evaluation(client):
    client.post("/api/evaluate", json={"scenario": "mfa_fatigue"}, headers=ANALYST)
    r = client.get("/api/identities/usr-billing.reyes", headers=ANALYST)
    assert r.status_code == 200
    body = r.json()
    assert body["identity"]["display_name"] == "Reyes"
    assert body["score"] >= 85 and body["severity_band"] == "critical"
    resources = {x["resource_id"] for x in body["reachable_sensitive_resources"]}
    assert {"res-billing-exports", "res-payroll-db"} <= resources
    assert body["alerts"], "compromised identity must show alerts"
    assert any(c["name"] == "signal" for c in body["risk"]["components"])


def test_graph_shape_and_path_highlight(client):
    client.post("/api/evaluate", json={"scenario": "mfa_fatigue"}, headers=ANALYST)
    r = client.get("/api/graph", params={"identity_id": "usr-billing.reyes"}, headers=ANALYST)
    assert r.status_code == 200
    body = r.json()
    node_ids = {n["id"] for n in body["nodes"]}
    assert "usr-billing.reyes" in node_ids and "res-billing-exports" in node_ids
    assert all("grant_id" in e for e in body["edges"])
    assert any(e["on_path"] for e in body["edges"]), "reachable path edges must be highlighted"


def test_case_detail_timeline_ordered_and_traceable(client):
    client.post("/api/evaluate", json={"scenario": "role_grant_abuse"}, headers=ANALYST)
    cases = client.get("/api/cases", headers=ANALYST).json()
    target = next(c for c in cases if c["identity_id"] == "usr-marcus.webb")
    detail = client.get(f"/api/cases/{target['case_id']}", headers=ANALYST).json()
    tl = detail["timeline"]
    assert len(tl) >= 3
    stamps = [t["timestamp"] for t in tl]
    assert stamps == sorted(stamps), "timeline must be chronological"
    for item in tl:
        assert item["kind"] in {"event", "alert"}
        assert item.get("event_id") or item.get("alert_id")


def test_unknown_scenario_404(client):
    assert client.post("/api/evaluate", json={"scenario": "nope"}, headers=ANALYST).status_code == 404


def test_baseline_produces_no_alerts(client):
    """The FP control: 288 normal events must stay silent (CI-enforced)."""
    from app.models import SessionLocal
    from app.bootstrap import detection_ctx, load_org, load_org as _lo
    from app.risk_engine import run_all_detections
    from app.ingestion import load_jsonl as lj
    events = lj(REPO / "datasets" / "normal" / "baseline.jsonl")
    with SessionLocal() as db:
        org = load_org(db)
        alerts = run_all_detections(events, detection_ctx(db, org))
    assert alerts == [], f"normal activity must not alert, got {len(alerts)}"
