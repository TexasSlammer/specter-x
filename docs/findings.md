# Engineering findings

The failures that shaped the design. Each entry: what broke, why, what changed. Every claim below is checkable in the code and the test suite — file and test references included.

## 1. "Explicit deny" had to win even when no allow existed

**Symptom.** The ground-truth fixture `usr-connor.wells → res-hr-portal` (a contractor with an explicit HR deny and no other grants) was initially attributed `no_allow_path`. Semantically defensible — and wrong: the *decision-relevant* fact is that an administrator wrote a deny, not that access merely wasn't granted.

**Fix.** Evaluate denies **before** any allow analysis, and report `explicit_deny` even when the route set is empty. The deny subject set is deliberately the whole expanded chain (identity, inherited groups, assumable principals) so a deny pinned on an assumable role can't be bypassed by an allow on the assumee.
*Where:* `attack_graph/permission_eval.py` (analysis order §1); test `test_denied_paths_*` in `tests/unit/test_attack_graph.py`.

## 2. Union semantics over-reads multi-route resources

**Symptom.** `usr-flores` could "reach" the backup vault from a datacenter ASN: a clean group allow existed, even though the *trust* route onto the break-glass role was ASN-gated. A union-of-routes reading certifies access the org explicitly tried to gate.

**Fix.** Fail-closed multi-route join: a resource is reachable only when **every** candidate route is valid under the context. One condition-gated route tightens all routes. This is stricter than pure union semantics — the tension is flagged in the module docstring and accepted because overclaiming reachability is the one failure a security tool must never have.
*Where:* `permission_eval.py` (§3a/3b, `_Route`); pinned by `test_flores_vault_datacenter_*`.

## 3. Impossible travel fired on the VPN control

**Symptom.** First adversarial pass: a San Antonio → Berlin sign-in pair 3 hours apart on a **VPN ASN** raised a critical travel alert. The math was "right"; the geography was fiction — VPN egress misattributes city-level origin routinely.

**Fix.** GeoIP-uncertainty rule: pairs on `vpn`/`mobile` ASNs are suppressed **entirely** (not downgraded) because the implied-speed input is meaningless. Same trip on datacenter ASNs still alerts.
*Where:* `risk_engine/detections.py` (`D3_SUPPRESS_ASN_TYPES`); adversarial tests in `tests/adversarial/test_fp_resistance.py`.

## 4. New-device detection punished hardware refresh

**Symptom.** A clinician's mid-baseline laptop replacement (new `device_id`, residential ASN, non-privileged identity) tripped the naive new-device rule. New devices are normal; only *whose* new device and *from where* is signal.

**Fix.** Promotion rule: a first-seen device alerts only when the identity is privileged **or** the ASN is `datacenter`. Everything else stays silent and is asserted silent by the adversarial suite.
*Where:* `d2_new_device_signin`; control event in `datasets/generator.py` (`baseline()`), tested in the adversarial suite.

## 5. Re-running a scenario duplicated alerts

**Symptom.** Clicking **Run scenario** twice in the UI doubled the alert queue: events dedupe by `event_id`, but alerts were minted fresh random ids (`alr-` + `secrets.token_hex`) on every evaluation — the same detection on the same evidence became two rows.

**Fix.** Content-addressed alert ids: `alr-` + SHA-256 over `(detection_id, identity_id, event_refs)`. Same detection + same evidence ⇒ same id ⇒ `db.get` hit ⇒ no insert. Evaluate is now idempotent end-to-end (events by `event_id`, alerts by fingerprint, cases by identity hash).
*Where:* `bootstrap._alert_fingerprint`; e2e test `test_09_scenario_replay_is_idempotent`.

## 6. The graph had to point along the attacker's walk

**Symptom.** `RESOURCE_POLICY` records are written from the resource's point of view ("this vault trusts `svc-ehr-backup`"). Stored orientation makes reachability unnavigable — edges would point *away* from the resource.

**Fix.** Flip resource-policy records at build time so every edge points principal → resource. The record orientation stays readable from the edge payload; the CONTRACTS §2 `kind` vocabulary is untouched and every screen edge still traces to one `grant_id`.
*Where:* `graph_builder._resource_policy_endpoints` + module docstring table.

## 7. Consent scopes are org config, not grants

**Symptom.** The obvious move — materializing "scope `Files.ReadWrite.All` unlocks `res-payroll-db`" as graph edges — would have added an edge kind the contract never defined, breaking the "every edge is a grant" invariant.

**Fix.** The scope→resource map rides on `graph.graph["scope_resources"]` and is consumed at evaluation time by the consent-delegation logic. Delegation without a matching scope delegates nothing ("a consent is not a blank cheque").
*Where:* `graph_builder.build` (deliberately-not-materialized note), `permission_eval._candidate_routes`.

## 8. Random ids made the dataset non-reproducible

**Symptom.** The first generator draft used `uuid4()` for event ids; regenerating "the same" dataset produced different bytes, so ground truth and datasets could silently drift apart.

**Fix.** Deterministic ids from a call counter + seed (`evt-` + md5(seed:n)); `random` is seed-pinned. Regeneration is byte-identical, which is asserted by the provenance workflow (`datasets/provenance.json`, `generator-1.0.0`).

## 9. The test suite silently depended on execution order

**Symptom.** Adding the e2e user-journey suite surfaced order coupling: integration tests asserted "first ingest accepts 288" and "exactly one audit row in the whole table" — both false once another suite touched the shared session-wide SQLite database first.

**Fix.** Assertions rewritten as invariants ("replay adds nothing", "exactly one audit row *for this target*") instead of state assumptions. The suite now passes under three different directory orderings — which is what a regression suite is for.
*Where:* `tests/integration/test_api.py`, `tests/e2e/test_user_journey.py`.
