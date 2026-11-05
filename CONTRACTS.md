# SPECTER X — Engineering Contracts (v1.0)

Single source of truth for all modules. If code and this file disagree, this file wins — propose a change, don't fork silently.

## 1. Canonical Event Schema (ingestion contract)

Every ingested event, regardless of source (Entra-style sign-in, CloudTrail-style API, OAuth consent), is normalized to:

```json
{
  "event_id": "evt-<uuid4 hex>",        // REQUIRED, unique, idempotency key
  "source": "entra|cloudtrail|oauth",   // REQUIRED enum
  "type": "signin|signinfailure|mfa_denied|consent_granted|role_assigned|api_call|session_revoked|account_disabled",
  "timestamp": "2026-11-05T09:14:00Z",  // REQUIRED RFC3339 UTC
  "identity_id": "usr-...",             // REQUIRED (actor)
  "attributes": {                        // type-specific, see below
    "ip": "203.0.113.7", "device_id": "dev-...", "user_agent": "...",
    "city": "San Antonio", "country": "US", "asn_type": "residential|mobile|vpn|datacenter|corporate",
    "mfa_method": "push", "result": "success|denied",
    "resource_id": "res-...", "app_id": "app-...", "scopes": ["Mail.ReadWrite"],
    "role": "grp-...", "session_id": "sess-..."
  },
  "raw": { }                             // optional original record
}
```

Rules: unknown `source`/`type` → REJECTED (HTTP 422, counted in `ingestion.rejected`). Missing required field → REJECTED. Duplicate `event_id` → ACCEPTED but NOT stored again (HTTP 200, response marks `duplicates`), zero double-count on replay. Attributes are free-form per type; validators check per-type required attributes.

## 2. Identity & Permission Model (graph contract)

Entities: `usr-*` users, `grp-*` groups (may nest, max depth 5), `app-*` OAuth apps/service principals, `res-*` resources, `role-*` directory roles.

Grant records (each has `grant_id`, `created_at`):
- `IDENTITY_POLICY_ALLOW`: subject(grantee) → action on resource, optional conditions `{ip_in: [...], time_window: "HH:MM-HH:MM", asn_type_in: [...]}`
- `IDENTITY_POLICY_DENY`: same shape; **explicit deny overrides any allow** (AWS semantics)
- `RESOURCE_POLICY`: resource → principal grant (cross-boundary access without identity allow)
- `TRUST_ASSUME`: principal may assume role/identity (`from_id` → `to_id`), optional conditions
- `GROUP_MEMBER`: user → group (transitive via nesting)
- `APP_CONSENT`: user/principal consented `app-*` with `scopes` (e.g. `Mail.ReadWrite`, `Files.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`); app acts within scopes toward resources mapped to those scopes
- `DIRECTORY_ROLE`: member → role (role → implicit high-privilege flag `privileged=true`)

Reachability semantics (permission_eval MUST implement exactly):
1. Collect every candidate path (direct grant, group expansion, role assumption chain ≤5 hops, consent delegation).
2. A path GRANTS only if: an allow-type edge chain exists AND no applicable DENY on any subject in the chain AND conditions (if any) hold under the evaluation context.
3. A resource reachable via RESOURCE_POLICY alone is reachable even without identity allow (document as "resource-policy exposure").
4. Denied paths are returned in results with `{"reachable": false, "reason": "explicit_deny"|"condition_mismatch"|"no_allow_path"|"trust_mismatch"}` — never silently dropped.
5. Evaluation context: `{ip, asn_type, time}` — fixtures and tests pass explicit contexts.

Graph output: `attack_graph.graph_builder.build(nx.DiGraph)`; nodes carry `kind`, `label`, `privileged`, `sensitive`; edges carry `grant_id`, `kind` from the list above.

`res-*` records carry `"sensitivity": "sensitive|internal|public"` — attack paths terminate at **sensitive** resources.

## 3. Detection Contract

`risk_engine.detections.DETECTIONS` = list of detector callables `detect(events, ctx) -> list[Alert]`.

```json
Alert = {
  "detection_id": "D1_mfa_fatigue",
  "severity": "critical|high|medium|low",
  "confidence": 0.0-1.0,
  "identity_id": "usr-...",
  "reason": "human string with concrete numbers",
  "event_refs": ["evt-...", ...],      // >=1, must exist in DB
  "false_positive_notes": "when this fires wrongly"
}
```

Detectors to ship (window analysis on normalized events):
- `D1_mfa_fatigue`: ≥5 `mfa_denied` then a `signin` success same identity within 30 min.
- `D2_new_device_signin`: success signin from `device_id` never seen before for that identity AND (`identity.privileged` OR `asn_type == "datacenter"`). New device on vpn/residential/mobile ASN alone is NOT alert-worthy (VPN/mobile IP churn is normal — that is the documented FP rule).
- `D3_impossible_travel`: two successes >500 km/h apart; SUPPRESSED (low confidence or skip) when either asn_type in {vpn, mobile} — GeoIP uncertainty rule; document in notes.
- `D4_risky_oauth_consent`: `consent_granted` where scopes intersect high-privilege set {`Files.ReadWrite.All`, `Mail.ReadWrite`, `RoleManagement.ReadWrite.Directory`} and app lacks `verified: true`.
- `D5_role_assignment_anomaly`: `role_assigned` to privileged group by grantor without admin directory role OR outside grantor's normal hours (±2h of any prior activity).
- `D6_service_account_interactive`: identity marked `kind=service_account` doing interactive signin from a never-seen IP.

Controls (normal behaviors that MUST NOT alert; part of test suite): corporate-VPN logins from new IPs (asn_type=vpn/corporate), service account batch runs from known IP, consent to a `verified: true` app with read-only scope, scheduled role activation by an admin during business hours.

## 4. Risk Scoring Contract (deterministic, explainable)

`risk_engine.scoring.score_identity(identity_id, alerts, graph, ctx) -> {"score": 0-100, "components": [...], "explanation": [...]}`:
- `signal_component`: 0–55 from max alert severity (critical 55, high 40, medium 25, low 10) + 5 per additional correlated alert (cap 15).
- `access_component`: 0–30 = 12 per reachable **sensitive** resource (cap 30) via the graph; 0 if none.
- `blast_component`: 0–15 = privileged identity 10, directory-role holder +5.
- Uncertainty: detections with confidence <0.6 contribute 60% weight (documented in explanation strings).
- Every component lists `justification` referencing alert ids / grant ids / resource ids. No ML. Same input → same output (unit-tested).

## 5. API Contract

Base path `/api`. Auth: `Authorization: Bearer <token>`; tokens in env `SPECTER_TOKENS` as `token:role` CSV, roles `analyst|admin`. 401 unknown token, 403 analyst calling admin-only. All list endpoints support `?limit=&offset=`.

- `POST /api/ingest` body `{"events": [CanonicalEvent...]}` → `{"accepted": n, "duplicates": n, "rejected": [{"event_id","error"}...]}` (admin or ingest role; analyst also allowed for demo replay)
- `GET /api/identities` → `[{identity_id, display_name, kind, department, score, severity_band}]`
- `GET /api/identities/{id}` → `{"identity": {..., "score": int, "severity_band": str}, "score": int, "severity_band": str, "risk": <score object with components+explanation>, "score_breakdown": <same>, "components": [...], "alerts": [...], "reachable_sensitive_resources": [{"resource_id","label","sensitivity","via","paths"}], "consented_apps": [{"app_id","scopes"}]}` (score is emitted flat AND nested so both simple and rich clients work)
- `POST /api/evaluate` body `{"scenario": "mfa_fatigue"}` → runs detectors over that scenario's events → alerts + scores (demo driver)
- `GET /api/alerts?severity=&limit=` → alert list, newest first
- `GET /api/cases` / `GET /api/cases/{case_id}` → case with correlated timeline (merged events+alerts sorted by time, each item carries `kind`, `event_id`/`alert_id`, summary) + `conclusion`
- `GET /api/graph?identity_id=` → `{nodes: [{id,label,kind,privileged,sensitive}], edges: [{from,to,kind,grant_id}]}` (vis-network shape)
- `POST /api/respond/consent_revoke|account_disable|session_revoke` body `{"app_id"|"identity_id", "confirm": true}` (admin ONLY; writes to response_audit table; simulation-only — never external calls; response includes `"simulated": true`)

## 6. Ground Truth Format (datasets/ground_truth.json)

```json
{
  "org": "Northstar Health",
  "reachable_paths": [{"identity_id": "...", "resource_id": "...", "ctx": {"ip":"...","asn_type":"corporate","time":"14:00"}, "expect": true}],
  "denied_paths":     [{"identity_id": "...", "resource_id": "...", "ctx": {...}, "expect": false, "reason": "explicit_deny"}],
  "attack_scenarios": {"mfa_fatigue": {"events_file": "attack-scenarios/mfa_fatigue.jsonl", "compromised": ["usr-dana.reyes"], "expected_detections": ["D1_mfa_fatigue", "D2_new_device_signin", "D4_risky_oauth_consent"], "min_score": 85}},
  "normal_baseline": {"events_file": "normal/baseline.jsonl", "max_alerts": 3, "expected_detections": []}
}
```

## 7. Engineering Rules

- Python 3.10+, type hints everywhere, `ruff`-clean style (no config enforcement required).
- Backend deps ONLY: fastapi, uvicorn, sqlalchemy, pydantic, networkx, httpx, pytest (+stdlib). No new deps without updating this file.
- DB: SQLAlchemy 2.x; SQLite file by default (`sqlite:///./specter.db`), `DATABASE_URL` env switches to Postgres — must work identically.
- Frontend: static files in `frontend/` served by FastAPI at `/`; **no build step, no npm**; vis-network vendored at `frontend/vendor/`. `app.js` uses `fetch('/api/...')` with the token from the login box.
- Tests: backend tests live in `backend/tests/` mirroring module layout; every acceptance number in the README must be produced by `benchmarks/evaluation.py`, which writes `benchmarks/results/*.json`.
- No module reads another track's internals — only these contracts + `backend/app/models.py`.
- Every finding/alert/case must be traceable to `event_id`s (acceptance: 100%).
