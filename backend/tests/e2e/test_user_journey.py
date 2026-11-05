"""E2E: the full recruiter journey over the HTTP API, in order.

This is the demo script a first-time user would follow after `uvicorn
app.main:app` — login, ingest, evaluate every labeled scenario, triage the
top-risk identity, read its attack graph, open the case, replay a scenario,
and fire a response action. It runs against the same app a real server would
serve (TestClient exercises the full ASGI stack including lifespan).
"""
from __future__ import annotations

from sqlalchemy import func, select

from conftest import ADMIN, ANALYST, REPO

from app.ingestion import load_jsonl

COMPROMISED = "usr-billing.reyes"  # dana.reyes — mfa_fatigue victim


def test_01_health_and_login_gate(client):
    assert client.get("/healthz").status_code == 200
    # the API is closed: no token / unknown token both fail before any data flows
    assert client.get("/api/identities").status_code == 401
    assert client.get("/api/identities", headers={"Authorization": "Bearer guess"}).status_code == 401
    assert client.get("/api/identities", headers=ANALYST).status_code == 200


def test_02_ingest_baseline(client):
    events = load_jsonl(REPO / "datasets" / "normal" / "baseline.jsonl")
    r = client.post("/api/ingest", json={"events": events}, headers=ANALYST).json()
    assert r["rejected"] == []
    # replay the same batch: zero new rows (idempotency by event_id), whatever
    # earlier tests may have ingested — the invariant is "replay adds nothing"
    r2 = client.post("/api/ingest", json={"events": events}, headers=ANALYST).json()
    assert r2["accepted"] == 0 and r2["duplicates"] == len(events)


def test_03_evaluate_all_scenarios(client):
    detected_any = set()
    for name in ("mfa_fatigue", "service_account_abuse", "impossible_travel", "role_grant_abuse"):
        body = client.post("/api/evaluate", json={"scenario": name}, headers=ANALYST).json()
        assert set(body["expected"]) <= {a["detection_id"] for a in body["alerts"]}, name
        detected_any |= {a["detection_id"] for a in body["alerts"]}
    # every detector D1..D6 earns its keep across the four labeled scenarios
    assert {f"D{i}" for i in range(1, 7)} <= {d.split("_")[0] for d in detected_any}


def test_04_top_risk_identity_is_the_compromised_privileged_identity(client):
    identities = client.get("/api/identities", headers=ANALYST).json()
    scores = [i["score"] for i in identities]
    assert scores == sorted(scores, reverse=True), "list must be ranked by risk"
    top = identities[0]
    assert top["score"] >= 85 and top["severity_band"] == "critical"


def test_05_identity_detail_evidence_chain(client):
    body = client.get(f"/api/identities/{COMPROMISED}", headers=ANALYST).json()
    assert body["score"] >= 85 and body["severity_band"] == "critical"
    # the score decomposes into named, justified components
    names = {c["name"] for c in body["components"]}
    assert names == {"signal", "access", "blast"}
    assert body["risk"]["explanation"], "every score must be explainable"
    # blast radius is grounded in the permission graph, not asserted
    resources = {r["resource_id"] for r in body["reachable_sensitive_resources"]}
    assert "res-billing-exports" in resources
    assert all(r["paths"] for r in body["reachable_sensitive_resources"]), "evidence chains required"


def test_06_attack_graph_shape(client):
    body = client.get("/api/graph", params={"identity_id": COMPROMISED}, headers=ANALYST).json()
    ids = {n["id"] for n in body["nodes"]}
    assert COMPROMISED in ids
    assert any(n["sensitive"] for n in body["nodes"]), "sensitive resources must be marked"
    assert all(e.get("grant_id") for e in body["edges"]), "every edge traces to a grant_id"
    assert any(e["on_path"] for e in body["edges"]), "reachable paths must be highlighted"


def test_07_case_timeline_traceable(client):
    cases = client.get("/api/cases", headers=ANALYST).json()
    case = next(c for c in cases if c["identity_id"] == COMPROMISED)
    detail = client.get(f"/api/cases/{case['case_id']}", headers=ANALYST).json()
    stamps = [t["timestamp"] for t in detail["timeline"]]
    assert stamps == sorted(stamps) and len(stamps) >= 3
    for item in detail["timeline"]:
        assert item["kind"] in {"event", "alert"}
        assert item.get("event_id") or item.get("alert_id")


def test_08_alerts_severity_filter_and_traceability(client):
    alerts = client.get("/api/alerts", headers=ANALYST).json()
    assert alerts, "labeled attacks must have produced alerts"
    crit = client.get("/api/alerts", params={"severity": "critical"}, headers=ANALYST).json()
    assert crit and all(a["severity"] == "critical" for a in crit)
    from app.models import Event, SessionLocal
    with SessionLocal() as db:
        ids = set(db.execute(select(Event.event_id)).scalars())
    for a in alerts:
        assert a["event_refs"] and set(a["event_refs"]) <= ids


def test_09_scenario_replay_is_idempotent(client):
    """Re-running a scenario must not duplicate alerts (content-addressed ids)."""
    before = client.get("/api/alerts", headers=ANALYST).json()
    client.post("/api/evaluate", json={"scenario": "mfa_fatigue"}, headers=ANALYST)
    after = client.get("/api/alerts", headers=ANALYST).json()
    assert len(after) == len(before), "replay must not mint duplicate alerts"


def test_10_response_actions_rbac_and_audit(client):
    # analyst is blocked (403) and nothing happens
    r = client.post("/api/respond/session_revoke",
                    json={"identity_id": COMPROMISED, "confirm": True}, headers=ANALYST)
    assert r.status_code == 403
    # admin succeeds and the action is audit-logged as a simulation
    r = client.post("/api/respond/session_revoke",
                    json={"identity_id": COMPROMISED, "confirm": True}, headers=ADMIN)
    assert r.status_code == 200
    body = r.json()
    assert body["simulated"] is True and body["audit_id"].startswith("aud-")
    from app.models import ResponseAudit, SessionLocal
    with SessionLocal() as db:
        rows = db.execute(select(ResponseAudit).where(
            ResponseAudit.target_id == COMPROMISED)).scalars().all()
        assert any(row.action == "session_revoke" for row in rows)
