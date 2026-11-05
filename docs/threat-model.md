# Threat model — SPECTER X itself

A security tool gets held to its own standard. This is the STRIDE-lite pass over SPECTER X as an attack surface, with the control that answers each threat and the test that proves it.

## Assets

- **Event store** — security telemetry (synthetic in the demo, real if connected to a tenant)
- **Authorization graph** — who can reach what; a map of your crown jewels
- **Response audit log** — record of containment actions
- **API tokens** — the only credentials in the system

## STRIDE-lite

| Component | Threat | Control | Verified by |
|---|---|---|---|
| Ingestion | Malformed payload DoS / parser crash | Strict validator: source/type whitelist, required fields, timestamp parsing; rejects never raise | `test_malformed_events_rejected` |
| Ingestion | Duplicate-injection (same event replayed to skew counts) | `event_id` primary key; replays counted, not stored | `test_ingest_replay_is_idempotent` |
| API | Token theft / enumeration | Bearer tokens only from env, constant 401s, no user enumeration detail | `test_missing_token_401`, `test_unknown_token_401` |
| API | Privilege escalation (analyst triggering response) | Role gate on all `/api/respond/*`; 403 without admin role | `test_analyst_cannot_respond_403` |
| API | Cross-tenant/cross-user reads | Single-tenant demo scope by design; no user-supplied tenancy anywhere | contract review (CONTRACTS §5) |
| Frontend | XSS via event strings (reasons, names, ids) | `esc()` on every rendered string; no `innerHTML` with unescaped data | `frontend/app.js` helper + manual audit |
| Graph API | Data exfiltration via reachability oracles | Read endpoints still require a valid token; demo ships zero real data | synthetic provenance (`datasets/provenance.json`) |
| Response | Destructive action abuse | Simulation-only by design; admin-only; every action writes an immutable audit row | `test_admin_respond_simulated` |
| Supply chain | Dependency compromise | Runtime deps: 5 packages (fastapi, uvicorn, sqlalchemy, pydantic, networkx); CI runs `pip-audit` + `bandit` | `.github/workflows/security.yml` |

## Abuse cases considered

- **Analyst with a valid demo token exfiltrating the graph** — accepted risk for a demo; mitigation for production would be per-user tokens, audit on reads, and field-level minimization. Documented, not hidden.
- **Attacker feeding forged sign-in events to poison risk scores** — the canonical schema carries source/identity/attributes without signatures. Real deployments must ingest from authenticated log pipelines (signed log streams, SIEM relay). Out of scope for the prototype, listed in `limitations.md`.
- **Score gaming** — the scoring model is deterministic and public (`risk_engine/scoring.py`). An attacker who knows it can act below thresholds; the counter is tuning + layered detections, which is why every weight sits in one testable place.

## What this model does NOT cover

The demo deployment (laptop/docker) has no TLS termination, no rate limiting, no secrets rotation. It is a workstation tool, not an internet-facing service — treat it as such.
