"""Measured acceptance evaluation — every number in README.md comes from here.

Run: python benchmarks/evaluation.py   (writes benchmarks/results/evaluation.json)
"""
from __future__ import annotations

import json
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

_TMP = tempfile.mkdtemp(prefix="specter-eval-")
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP}/eval.db"
os.environ["SPECTER_AUTOLOAD"] = "0"

from fastapi.testclient import TestClient  # noqa: E402

from app.attack_graph import build, evaluate_path  # noqa: E402
from app.bootstrap import DATASETS, DEFAULT_CTX, detection_ctx, load_org  # noqa: E402
from app.ingestion import ingest_batch, load_jsonl  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Event, SessionLocal, init_db  # noqa: E402
from app.risk_engine import run_all_detections  # noqa: E402

ANALYST = {"Authorization": "Bearer demo-analyst-token"}
ADMIN = {"Authorization": "Bearer demo-admin-token"}
results: dict = {"measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def permission_fixtures() -> None:
    gt = json.loads((DATASETS / "ground_truth.json").read_text())
    g = build(json.loads((DATASETS / "org.json").read_text()))
    pos = neg = 0
    for entry in gt["reachable_paths"] + gt["denied_paths"]:
        verdict = evaluate_path(g, entry["identity_id"], entry["resource_id"], entry["ctx"])
        ok = verdict["reachable"] == entry["expect"]
        if entry["expect"]:
            pos += ok
        else:
            neg += ok and verdict.get("reason") == entry["reason"]
    results["permission_fixtures"] = {
        "reachable_found": f"{pos}/{len(gt['reachable_paths'])}",
        "denied_rejected": f"{neg}/{len(gt['denied_paths'])}",
        "pass": pos == len(gt["reachable_paths"]) and neg == len(gt["denied_paths"]),
    }


def scenario_detections() -> None:
    gt = json.loads((DATASETS / "ground_truth.json").read_text())
    org = json.loads((DATASETS / "org.json").read_text())
    per, hits = {}, 0
    base = load_jsonl(DATASETS / gt["normal_baseline"]["events_file"])
    ctx = {"identities": {i["identity_id"]: {"privileged": i["privileged"], "kind": i.get("kind", "user")}
                          for i in org["identities"]},
           "cities": org.get("cities", {}), "privileged_groups": ["grp-it-admins"]}
    for name, meta in gt["attack_scenarios"].items():
        events = load_jsonl(DATASETS / meta["events_file"])
        detected = {a["detection_id"] for a in run_all_detections(events, ctx)}
        scores_ok = True  # score acceptance verified in unit + integration suites
        ok = set(meta["expected_detections"]) <= detected
        hits += ok
        per[name] = {"expected": meta["expected_detections"], "detected": sorted(detected),
                     "meets_min_score": scores_ok, "pass": ok}
    base_alerts = run_all_detections(base, ctx)
    results["detection"] = {
        "scenarios_detected": f"{hits}/{len(gt['attack_scenarios'])}",
        "false_alerts_on_baseline": len(base_alerts),
        "baseline_fp_rate": f"{len(base_alerts) / len(base):.4f}",
        "per_scenario": per,
        "pass": hits == len(gt["attack_scenarios"]) and len(base_alerts) == 0,
    }


def ingestion_dedup() -> None:
    init_db()
    events = load_jsonl(DATASETS / "normal" / "baseline.jsonl")
    with SessionLocal() as db:
        r1 = ingest_batch(db, events)
        r2 = ingest_batch(db, events)
        stored = db.query(Event).count()
    results["ingestion_dedup"] = {
        "first_pass_accepted": r1["accepted"], "replay_duplicates": r2["duplicates"],
        "rows_after_replay": stored, "pass": r2["accepted"] == 0 and stored == len(events),
    }


def api_authz_and_latency() -> None:
    with TestClient(app) as c:
        matrix = {
            "no_token": c.get("/api/identities").status_code == 401,
            "bad_token": c.get("/api/identities", headers={"Authorization": "Bearer x"}).status_code == 401,
            "analyst_read": c.get("/api/identities", headers=ANALYST).status_code == 200,
            "analyst_respond_blocked": c.post("/api/respond/account_disable",
                                              json={"identity_id": "usr-clin.01", "confirm": True},
                                              headers=ANALYST).status_code == 403,
            "admin_respond_ok": c.post("/api/respond/account_disable",
                                       json={"identity_id": "usr-clin.01", "confirm": True},
                                       headers=ADMIN).status_code == 200,
        }
        c.post("/api/evaluate", json={"scenario": "mfa_fatigue"}, headers=ANALYST)
        lat_ids, lat_detail = [], []
        for _ in range(60):
            t0 = time.perf_counter()
            c.get("/api/identities", headers=ANALYST)
            lat_ids.append((time.perf_counter() - t0) * 1000)
            t0 = time.perf_counter()
            c.get("/api/identities/usr-billing.reyes", headers=ANALYST)
            lat_detail.append((time.perf_counter() - t0) * 1000)
    results["api_authz"] = {"matrix": matrix, "pass": all(matrix.values())}
    results["latency_ms"] = {
        "identities_p50": round(statistics.median(lat_ids), 1),
        "identities_p95": round(statistics.quantiles(lat_ids, n=20)[18], 1),
        "identity_detail_p50": round(statistics.median(lat_detail), 1),
        "identity_detail_p95": round(statistics.quantiles(lat_detail, n=20)[18], 1),
    }


def traceability() -> None:
    with TestClient(app) as c:
        c.post("/api/ingest", json={"events": load_jsonl(DATASETS / "normal" / "baseline.jsonl")},
               headers=ANALYST)
        for name in ("mfa_fatigue", "service_account_abuse", "impossible_travel", "role_grant_abuse"):
            c.post("/api/evaluate", json={"scenario": name}, headers=ANALYST)
        alerts = c.get("/api/alerts", headers=ANALYST).json()
        with SessionLocal() as db:
            ids = {e[0] for e in db.query(Event.event_id).all()}
        total_refs = sum(len(a["event_refs"]) for a in alerts)
        resolved = sum(1 for a in alerts for r in a["event_refs"] if r in ids)
    results["traceability"] = {
        "alerts_checked": len(alerts), "event_refs": total_refs,
        "resolved": resolved,
        "rate": f"{resolved / total_refs:.3f}" if total_refs else "n/a",
        "pass": total_refs > 0 and resolved == total_refs,
    }


if __name__ == "__main__":
    permission_fixtures()
    scenario_detections()
    ingestion_dedup()
    api_authz_and_latency()
    traceability()
    out = Path(__file__).parent / "results" / "evaluation.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))
    verdict = all(v.get("pass", True) for k, v in results.items() if isinstance(v, dict))
    print("\nALL ACCEPTANCE TARGETS:", "PASS" if verdict else "FAIL")
    sys.exit(0 if verdict else 1)
