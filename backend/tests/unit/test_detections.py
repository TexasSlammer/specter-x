"""Track B unit tests — detectors D1..D6 (CONTRACTS §3).

Acceptance covered here:
1. every ground-truth scenario yields at least its expected_detections;
2. normal/baseline.jsonl yields ZERO alerts (FP regression, 288 controls);
4. no alert has empty event_refs and every ref exists in the input events.
"""
from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))

from app.risk_engine.detections import (  # noqa: E402
    DETECTIONS,
    d1_mfa_fatigue,
    d2_new_device_signin,
    d3_impossible_travel,
    d4_risky_oauth_consent,
    d5_role_assignment_anomaly,
    d6_service_account_interactive,
    run_all_detections,
)

DATASETS = ROOT / "datasets"
ALERT_KEYS = {
    "detection_id",
    "severity",
    "confidence",
    "identity_id",
    "reason",
    "event_refs",
    "false_positive_notes",
}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}


# ------------------------------------------------------------------ fixtures


def load_jsonl(path: Path) -> list[dict]:
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    rows.sort(key=lambda e: e["timestamp"])  # canonical order per acceptance
    return rows


def load_org() -> dict:
    return json.loads((DATASETS / "org.json").read_text())


def load_ground_truth() -> dict:
    return json.loads((DATASETS / "ground_truth.json").read_text())


def build_ctx(org: dict) -> dict:
    """Detector ctx per CONTRACTS §3: identity metadata + city coordinates."""
    identities = {
        i["identity_id"]: {
            "privileged": bool(i.get("privileged", False)),
            "kind": i.get("kind", "user"),
        }
        for i in org["identities"]
    }
    groups: dict[str, set[str]] = {}
    for g in org["grants"]:
        if g["kind"] == "GROUP_MEMBER":
            groups.setdefault(g["to_id"], set()).add(g["from_id"])
    privileged_groups = sorted(
        gid for gid, members in groups.items()
        if any(identities.get(m, {}).get("privileged", False) for m in members)
    )
    return {
        "identities": identities,
        "cities": {k: tuple(v) for k, v in org["cities"].items()},
        "privileged_groups": privileged_groups,
    }


ORG = load_org()
CTX = build_ctx(ORG)
GT = load_ground_truth()
BASELINE = load_jsonl(DATASETS / "normal" / "baseline.jsonl")
SCENARIO_EVENTS: dict[str, list[dict]] = {
    name: load_jsonl(DATASETS / spec["events_file"]) for name, spec in GT["attack_scenarios"].items()
}


def scenario_alerts(name: str) -> list[dict]:
    return run_all_detections(SCENARIO_EVENTS[name], CTX)


def synth_event(event_id: str, type_: str, timestamp: str, identity_id: str, **attrs) -> dict:
    return {
        "event_id": event_id,
        "source": "entra",
        "type": type_,
        "timestamp": timestamp,
        "identity_id": identity_id,
        "attributes": attrs,
        "raw": {},
    }


def sign(identity_id: str, ts: str, **attrs) -> dict:
    base = {"ip": "198.51.100.2", "result": "success", "asn_type": "residential", "city": "San Antonio"}
    base.update(attrs)
    return synth_event(f"evt-{identity_id}-{ts}", "signin", ts, identity_id, **base)


# ---------------------------------------------------- 1. ground-truth coverage


def test_all_six_detectors_registered() -> None:
    assert [fn.detection_id for fn in DETECTIONS] == [
        "D1_mfa_fatigue",
        "D2_new_device_signin",
        "D3_impossible_travel",
        "D4_risky_oauth_consent",
        "D5_role_assignment_anomaly",
        "D6_service_account_interactive",
    ]


def test_every_scenario_yields_expected_detections() -> None:
    for name, spec in GT["attack_scenarios"].items():
        got = {a["detection_id"] for a in scenario_alerts(name)}
        expected = set(spec["expected_detections"])
        assert expected <= got, f"{name}: expected {expected}, got {got}"


def test_baseline_yields_zero_alerts() -> None:
    """288 normal-behavior control events: not a single alert may fire."""
    alerts = run_all_detections(BASELINE, CTX)
    assert alerts == []


# ------------------------------------- 4. traceability / contract-shaped alerts


def test_all_scenario_alerts_are_contract_shaped_with_valid_refs() -> None:
    all_alerts: list[tuple[str, dict]] = []
    for name in GT["attack_scenarios"]:
        all_alerts += [(name, a) for a in scenario_alerts(name)]
    assert all_alerts, "scenarios must produce alerts"
    for name, alert in all_alerts:
        assert set(alert) == ALERT_KEYS, f"{name}: unexpected alert keys {set(alert)}"
        assert alert["severity"] in VALID_SEVERITIES
        assert 0.0 <= alert["confidence"] <= 1.0
        assert alert["identity_id"]
        assert alert["reason"]
        assert alert["false_positive_notes"]
        assert alert["event_refs"], f"{name}/{alert['detection_id']}: empty event_refs"
        known = {e["event_id"] for e in SCENARIO_EVENTS[name]}
        unknown = set(alert["event_refs"]) - known
        assert not unknown, f"{name}/{alert['detection_id']}: refs not in events: {unknown}"


def test_detection_runs_are_deterministic() -> None:
    for name in GT["attack_scenarios"]:
        once = run_all_detections(SCENARIO_EVENTS[name], CTX)
        twice = run_all_detections(copy.deepcopy(SCENARIO_EVENTS[name]), CTX)
        assert once == twice


# ------------------------------------------------------ per-scenario specifics


def test_mfa_fatigue_d1_reason_has_concrete_numbers() -> None:
    alerts = scenario_alerts("mfa_fatigue")
    d1 = next(a for a in alerts if a["detection_id"] == "D1_mfa_fatigue")
    assert d1["severity"] == "critical" and d1["confidence"] == 0.95
    assert d1["identity_id"] == "usr-billing.reyes"
    assert "7 MFA denials" in d1["reason"]
    assert "45.134.20.18" in d1["reason"]
    assert "09:17" in d1["reason"]
    assert len(d1["event_refs"]) == 8  # 7 denials + the following success


def test_mfa_fatigue_d2_medium_d4_high() -> None:
    alerts = scenario_alerts("mfa_fatigue")
    d2 = next(a for a in alerts if a["detection_id"] == "D2_new_device_signin")
    assert d2["severity"] == "medium" and d2["confidence"] == 0.8  # datacenter ASN, non-privileged
    d4 = next(a for a in alerts if a["detection_id"] == "D4_risky_oauth_consent")
    assert d4["severity"] == "high" and d4["confidence"] == 0.9
    assert "Files.ReadWrite.All" in d4["reason"] and "app-office-helper" in d4["reason"]


def test_impossible_travel_d3_speed_and_refs() -> None:
    alerts = scenario_alerts("impossible_travel")
    d3 = [a for a in alerts if a["detection_id"] == "D3_impossible_travel"]
    assert len(d3) == 1
    a = d3[0]
    assert a["identity_id"] == "usr-okafor.exec"
    assert a["severity"] == "high" and a["confidence"] == 0.85
    match = re.search(r"(\d+) km/h implied", a["reason"])
    assert match and int(match.group(1)) >= 500
    assert "San Antonio -> Lagos" in a["reason"]
    assert len(a["event_refs"]) == 2
    d2 = [a for a in alerts if a["detection_id"] == "D2_new_device_signin"]
    assert d2 and all(x["severity"] == "high" for x in d2)  # privileged executive


def test_role_grant_abuse_d5_attaches_to_target() -> None:
    alerts = scenario_alerts("role_grant_abuse")
    d5 = [a for a in alerts if a["detection_id"] == "D5_role_assignment_anomaly"]
    assert len(d5) == 1
    a = d5[0]
    # attached to the TARGET identity, not the grantor/actor
    assert a["identity_id"] == "usr-marcus.webb"
    assert a["severity"] == "high" and a["confidence"] == 0.9  # grp-it-admins is privileged
    assert "usr-connor.wells" in a["reason"]  # grantor named in the reason
    assert len(a["event_refs"]) == 1
    ref_event = next(e for e in SCENARIO_EVENTS["role_grant_abuse"] if e["event_id"] == a["event_refs"][0])
    assert ref_event["type"] == "role_assigned"
    d2 = [a for a in alerts if a["detection_id"] == "D2_new_device_signin" and a["identity_id"] == "usr-marcus.webb"]
    assert d2  # datacenter + privileged IT admin


def test_service_account_abuse_d6() -> None:
    alerts = scenario_alerts("service_account_abuse")
    d6 = [a for a in alerts if a["detection_id"] == "D6_service_account_interactive"]
    assert len(d6) == 1
    a = d6[0]
    assert a["identity_id"] == "svc-reporting"
    assert a["severity"] == "high" and a["confidence"] == 0.85
    assert "91.240.118.6" in a["reason"]


# ------------------------------------------------------------- D1 thresholding


def test_d1_requires_five_denials() -> None:
    denials = [
        synth_event(f"evt-d{i}", "mfa_denied", f"2026-11-02T09:0{i}:00Z", "usr-x", ip="1.2.3.4", result="denied")
        for i in range(4)
    ]
    ok = sign("usr-x", "2026-11-02T09:15:00Z", device_id="dev-x")
    assert d1_mfa_fatigue(denials + [ok], {}) == []
    denials.append(synth_event("evt-d4", "mfa_denied", "2026-11-02T09:04:00Z", "usr-x", ip="1.2.3.4", result="denied"))
    alerts = d1_mfa_fatigue(denials + [ok], {})
    assert len(alerts) == 1 and alerts[0]["detection_id"] == "D1_mfa_fatigue"


def test_d1_success_outside_window_does_not_fire() -> None:
    denials = [
        synth_event(f"evt-d{i}", "mfa_denied", f"2026-11-02T09:0{i}:00Z", "usr-x", ip="1.2.3.4", result="denied")
        for i in range(5)
    ]
    late = sign("usr-x", "2026-11-02T09:41:00Z", device_id="dev-x")  # > 30 min after last denial
    assert d1_mfa_fatigue(denials + [late], {}) == []


# ------------------------------------------------------------- D2 FP controls


def test_d2_asn_and_privilege_rules() -> None:
    ctx = {"identities": {"usr-a": {"privileged": False, "kind": "user"}, "usr-p": {"privileged": True, "kind": "user"}}}
    cases = [
        ("residential", "usr-a", 0),
        ("vpn", "usr-a", 0),
        ("mobile", "usr-a", 0),
        ("corporate", "usr-a", 0),
        ("datacenter", "usr-a", 1),  # datacenter ASN -> alert even for regular users
        ("vpn", "usr-p", 1),  # privileged -> alert even on VPN (contract refinement)
        ("residential", "usr-p", 1),
    ]
    for asn, iid, expected_n in cases:
        events = [sign(iid, "2026-11-02T09:00:00Z", device_id=f"dev-{asn}-{iid}", asn_type=asn)]
        alerts = d2_new_device_signin(events, ctx)
        assert len(alerts) == expected_n, f"asn={asn} identity={iid}: {alerts}"
        if expected_n:
            want = "high" if iid == "usr-p" else "medium"
            assert alerts[0]["severity"] == want


def test_d2_reused_device_is_not_new() -> None:
    ctx = {"identities": {"usr-p": {"privileged": True, "kind": "user"}}}
    events = [
        sign("usr-p", "2026-11-02T09:00:00Z", device_id="dev-p"),
        sign("usr-p", "2026-11-03T09:00:00Z", device_id="dev-p"),
    ]
    assert d2_new_device_signin(events, ctx) == []


# ------------------------------------------------------------- D3 FP controls


def _travel_pair(asn1: str, asn2: str, t2: str = "2026-11-02T21:10:00Z") -> list[dict]:
    return [
        sign("usr-t", "2026-11-02T20:10:00Z", device_id="dev-t1", asn_type=asn1, city="San Antonio"),
        sign("usr-t", t2, device_id="dev-t2", asn_type=asn2, city="Lagos"),
    ]


CITIES = {"San Antonio": (29.42, -98.49), "Lagos": (6.52, 3.37), "Austin": (30.27, -97.74)}


def test_d3_fires_on_fast_cross_city_pair() -> None:
    alerts = d3_impossible_travel(_travel_pair("residential", "datacenter"), {"cities": CITIES})
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "high" and alerts[0]["confidence"] == 0.85
    assert len(alerts[0]["event_refs"]) == 2


def test_d3_suppresses_vpn_and_mobile_pairs() -> None:
    """GeoIP-uncertainty FP rule: vpn/mobile pairs are skipped entirely."""
    for a1, a2 in [("vpn", "datacenter"), ("residential", "vpn"), ("mobile", "mobile")]:
        assert d3_impossible_travel(_travel_pair(a1, a2), {"cities": CITIES}) == [], (a1, a2)


def test_d3_ignores_slow_pairs_and_unknown_cities() -> None:
    slow = [
        sign("usr-t", "2026-11-01T09:00:00Z", device_id="dev-t1", city="San Antonio"),
        sign("usr-t", "2026-11-02T09:00:00Z", device_id="dev-t2", city="Austin"),  # ~128 km over 24 h
    ]
    assert d3_impossible_travel(slow, {"cities": CITIES}) == []
    unknown = _travel_pair("residential", "datacenter")
    unknown[1]["attributes"]["city"] = "Atlantis"
    assert d3_impossible_travel(unknown, {"cities": CITIES}) == []


# ------------------------------------------------------------- D4 FP controls


def test_d4_scope_and_verified_rules() -> None:
    def consent(event_id: str, scopes: list[str], verified: bool) -> dict:
        return synth_event(event_id, "consent_granted", "2026-11-02T09:00:00Z", "usr-x", app_id="app-x", scopes=scopes, verified=verified)

    risky = ["Files.ReadWrite.All"]
    assert len(d4_risky_oauth_consent([consent("evt-c1", risky, False)], {})) == 1
    assert d4_risky_oauth_consent([consent("evt-c2", risky, True)], {}) == []  # verified control
    assert d4_risky_oauth_consent([consent("evt-c3", ["Reports.Read"], False)], {}) == []  # read-only control
    got = d4_risky_oauth_consent([consent("evt-c4", ["Mail.ReadWrite", "Mail.Read"], False)], {})
    assert len(got) == 1 and "Mail.ReadWrite" in got[0]["reason"]


# ------------------------------------------------------------- D5 FP controls


def test_d5_admin_during_business_hours_is_control() -> None:
    ctx = {"identities": {"usr-admin": {"privileged": True, "kind": "user"}}, "privileged_groups": ["grp-it-admins"]}
    events = [
        sign("usr-admin", "2026-10-19T09:30:00Z", device_id="dev-a"),
        sign("usr-admin", "2026-10-20T09:45:00Z", device_id="dev-a"),
        synth_event(
            "evt-role", "role_assigned", "2026-10-21T10:05:00Z", "usr-admin",
            role="grp-it-admins", target_id="usr-b", grantor_has_admin=True,
        ),
    ]
    assert d5_role_assignment_anomaly(events, ctx) == []


def test_d5_non_admin_or_odd_hours_fires_on_target() -> None:
    ctx = {"identities": {"usr-c": {"privileged": False, "kind": "user"}}, "privileged_groups": ["grp-it-admins"]}
    events = [
        synth_event(
            "evt-role", "role_assigned", "2026-11-02T03:12:00Z", "usr-c",
            role="grp-it-admins", target_id="usr-t", grantor_has_admin=False,
        ),
    ]
    alerts = d5_role_assignment_anomaly(events, ctx)
    assert len(alerts) == 1
    assert alerts[0]["identity_id"] == "usr-t"  # attached to the target
    assert alerts[0]["severity"] == "high"
    # admin flag missing entirely -> treated as lacking admin evidence (conservative)
    events2 = [synth_event("evt-role2", "role_assigned", "2026-11-02T10:00:00Z", "usr-c", role="grp-it-admins", target_id="usr-t")]
    alerts2 = d5_role_assignment_anomaly(events2, ctx)
    assert len(alerts2) == 1 and alerts2[0]["identity_id"] == "usr-t"


def test_d5_ignores_non_privileged_groups() -> None:
    ctx = {"privileged_groups": ["grp-it-admins"]}
    events = [
        synth_event(
            "evt-role", "role_assigned", "2026-11-02T03:12:00Z", "usr-c",
            role="grp-billing", target_id="usr-t", grantor_has_admin=False,
        ),
    ]
    assert d5_role_assignment_anomaly(events, ctx) == []


# ------------------------------------------------------------- D6 FP controls


def test_d6_service_account_rules() -> None:
    ctx = {
        "identities": {
            "svc-a": {"privileged": False, "kind": "service_account"},
            "usr-u": {"privileged": False, "kind": "user"},
        }
    }
    batch = sign("svc-a", "2026-11-02T01:15:00Z", device_id="dev-svc", ip="198.51.100.9", interactive=False)
    assert d6_service_account_interactive([batch], ctx) == []  # non-interactive control

    first = sign("svc-a", "2026-11-02T22:40:00Z", device_id="dev-svc", ip="91.240.118.6", interactive=True)
    followup = synth_event("evt-api", "api_call", "2026-11-02T22:46:00Z", "svc-a", ip="91.240.118.6")
    again = sign("svc-a", "2026-11-02T23:40:00Z", device_id="dev-svc", ip="91.240.118.6", interactive=True)
    alerts = d6_service_account_interactive([first, followup, again], ctx)
    assert len(alerts) == 1  # fires once on first-seen IP only
    assert alerts[0]["identity_id"] == "svc-a"

    human = sign("usr-u", "2026-11-02T22:40:00Z", device_id="dev-u", ip="91.240.118.6", interactive=True)
    assert d6_service_account_interactive([human], ctx) == []  # kind=user control


def test_baseline_service_accounts_have_no_signins_so_d6_stays_silent() -> None:
    svc_ids = {i["identity_id"] for i in ORG["identities"] if i["kind"] == "service_account"}
    assert any(e["identity_id"] in svc_ids for e in BASELINE)  # baseline does contain svc activity
    assert all(e["type"] != "signin" for e in BASELINE if e["identity_id"] in svc_ids)
