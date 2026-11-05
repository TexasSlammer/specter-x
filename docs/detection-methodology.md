# Detection methodology

Six behavioral detectors, each with an explicit rule, a severity/confidence rationale, and documented false-positive suppression. Every alert carries `event_refs` (evidence), a human reason with concrete numbers, and `false_positive_notes`. The baseline regression — 288 normal events produce zero alerts — runs in CI.

| ID | Rule | Severity / confidence |
|---|---|---|
| D1 MFA fatigue | ≥5 `mfa_denied` for one identity, then a successful `signin` within 30 min | critical, 0.95 |
| D2 New-device sign-in | Successful sign-in from a `device_id` never seen for that identity AND (privileged identity OR `asn_type == datacenter`) | medium (0.8); high if privileged |
| D3 Impossible travel | Two successes >500 km/h implied (haversine over city coordinates) | high, 0.85 |
| D4 Risky OAuth consent | `consent_granted` with scopes in {`Files.ReadWrite.All`, `Mail.ReadWrite`, `RoleManagement.ReadWrite.Directory`} and app not `verified` | high, 0.9 |
| D5 Role-assignment anomaly | `role_assigned` to a privileged group by a grantor without an admin directory role OR outside their established activity hours (±2h) | high, 0.9 |
| D6 Service-account interactive logon | `kind=service_account` performing interactive sign-in from a never-seen IP | high, 0.85 |

## False-positive suppression rules (the important part)

Raw anomaly signals are noisy. Each detector ships with the suppression rule that keeps it usable, and each rule is a regression test:

1. **D2 ASN rule.** New device alone proves nothing: VPN clients and mobile carriers rotate exit addresses daily. A new device alerts only for privileged identities or datacenter ASNs; new device on vpn/residential/mobile stays silent. *Adversarial test: laptop-refresh scenario (residential, non-privileged) → no alert.*
2. **D3 GeoIP-uncertainty rule.** Implied-speed math over city centroids is fiction when either hop rides a VPN or mobile ASN — the "impossible" trip is usually the ASN lying about location. Such pairs are skipped entirely rather than downgraded. *Adversarial test: SA→Berlin via VPN in 3h → no alert; the same trip on datacenter ASNs → high alert.*
3. **D4 verified-publisher rule.** Consent to a `verified: true` app with read-only scope is normal IT onboarding. Only unverified apps with write/high-privilege scopes alert.
4. **D5 admin + business-hours rule.** Admins grant roles during work hours all the time. Suppressed when the grantor holds an admin directory role AND the grant lands within ±2h of their established activity window.
5. **D6 known-IP rule.** Service accounts run from the same host for years. Only an interactive sign-in from a never-seen IP alerts; batch `api_call` activity never does.

## Why deterministic rules, not ML

With ~300 labeled events, a trained model would memorize the seed and claim 99% recall it would not survive contact with a real tenant. The rule layer is auditable: an analyst can read D1 in one screen and argue with it. Weights live in one module (`risk_engine/scoring.py`) so tuning is a diff, not a retraining job. ML becomes interesting only with real labeled telemetry at volume — stated in `limitations.md`, not pretended here.

## Scoring model

Deterministic 0–100: behavior signals (0–55 by worst severity, +5 per correlated alert, cap 15) + access blast radius (12 per **reachable** sensitive resource via the permission graph, cap 30) + privilege bonus (privileged identity +10, directory role +5). Alerts below 0.6 confidence weigh 60%. Every component emits a justification string citing alert ids, grant ids, and resource ids — the number on screen decomposes to evidence on demand. Same input, same score, unit-tested.

## Measured outcome

`benchmarks/results/evaluation.json`: 4/4 labeled scenarios detected with all expected detectors firing, minimum scores met (MFA-fatigue victim 94/critical), 0 alerts on the 288-event normal baseline, 28/28 alert→event references resolved.
