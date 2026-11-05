"""Track B unit tests — deterministic risk scoring (CONTRACTS §4).

Acceptance covered here:
3. dana.reyes-style case (D1 + D2 + D4, two reachable sensitive resources)
   scores >= 85 -> band "critical";
   service-account-only case (1x D6, no reachable sensitive) is >= 40 and < 70;
   determinism: identical inputs -> identical output dict.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))

from app.risk_engine.scoring import (  # noqa: E402
    ACCESS_COMPONENT_CAP,
    BLAST_COMPONENT_CAP,
    CORRELATION_BONUS_CAP,
    score_identity,
)


def alert(detection_id: str, severity: str, confidence: float, *refs: str) -> dict:
    return {
        "detection_id": detection_id,
        "severity": severity,
        "confidence": confidence,
        "identity_id": "usr-under-test",
        "reason": f"{detection_id} fired",
        "event_refs": list(refs) or ["evt-x"],
        "false_positive_notes": "n/a",
    }


DANA_ALERTS = [
    alert("D1_mfa_fatigue", "critical", 0.95, "evt-d1", "evt-d2"),
    alert("D2_new_device_signin", "medium", 0.8, "evt-d3"),
    alert("D4_risky_oauth_consent", "high", 0.9, "evt-d4"),
]
DANA_ACCESS = {
    "reachable_sensitive": ["res-billing-exports", "res-payroll-db"],
    "privileged": False,
    "directory_role": False,
}


# ------------------------------------------------------------- acceptance no.3


def test_dana_reyes_style_case_is_critical() -> None:
    result = score_identity("usr-billing.reyes", DANA_ALERTS, DANA_ACCESS)
    # signal: 55 (critical) + min(15, 3x5) = 70; access: min(30, 2x12) = 24; blast: 0
    assert result["score"] == 94
    assert result["score"] >= 85
    assert result["severity_band"] == "critical"
    assert result["identity_id"] == "usr-billing.reyes"
    points = {c["name"]: c["points"] for c in result["components"]}
    assert points == {"signal": 55 + CORRELATION_BONUS_CAP, "access": 24, "blast": 0}
    assert len(result["components"]) == 3
    assert all(c["justification"] for c in result["components"])
    assert any("res-billing-exports" in c["justification"] for c in result["components"])
    assert any("res-payroll-db" in c["justification"] for c in result["components"])
    assert any("D1_mfa_fatigue" in c["justification"] for c in result["components"])
    assert any("= 94" in line for line in result["explanation"])


def test_service_account_only_case_is_medium() -> None:
    alerts = [alert("D6_service_account_interactive", "high", 0.85, "evt-s1")]
    result = score_identity("svc-reporting", alerts, {"reachable_sensitive": [], "privileged": False, "directory_role": False})
    # signal: 40 (high) + min(15, 1x5) = 45; no access, no blast
    assert result["score"] == 45
    assert 40 <= result["score"] < 70
    assert result["severity_band"] == "medium"
    assert {c["points"] for c in result["components"]} == {45, 0}


def test_scoring_is_deterministic() -> None:
    once = score_identity("usr-billing.reyes", copy.deepcopy(DANA_ALERTS), copy.deepcopy(DANA_ACCESS))
    twice = score_identity("usr-billing.reyes", copy.deepcopy(DANA_ALERTS), copy.deepcopy(DANA_ACCESS))
    assert once == twice
    # alert order in the input list must not change the outcome either
    shuffled = score_identity("usr-billing.reyes", list(reversed(DANA_ALERTS)), DANA_ACCESS)
    assert shuffled == once


# ------------------------------------------------------- uncertainty weighting


def test_low_confidence_alerts_weigh_sixty_percent() -> None:
    shaky = [alert("D2_new_device_signin", "high", 0.5, "evt-low")]
    result = score_identity("usr-x", shaky, {"reachable_sensitive": [], "privileged": False, "directory_role": False})
    # high = 40 pts, confidence 0.5 < 0.6 -> 40 * 0.6 = 24; bonus 3 instead of 5
    points = {c["name"]: c["points"] for c in result["components"]}
    assert points["signal"] == 27
    assert result["score"] == 27
    assert any("60%" in line and "D2_new_device_signin" in line for line in result["explanation"])


def test_confident_alerts_are_not_weighted_down() -> None:
    solid = [alert("D6_service_account_interactive", "high", 0.85, "evt-ok")]
    result = score_identity("usr-x", solid, {"reachable_sensitive": [], "privileged": False, "directory_role": False})
    assert {c["name"]: c["points"] for c in result["components"]}["signal"] == 45


# --------------------------------------------------------------- caps & bands


def test_access_component_caps_at_30() -> None:
    alerts = [alert("D1_mfa_fatigue", "critical", 0.95, "evt-a")]
    access = {"reachable_sensitive": ["res-a", "res-b", "res-c"], "privileged": False, "directory_role": False}
    result = score_identity("usr-x", alerts, access)
    points = {c["name"]: c["points"] for c in result["components"]}
    assert points["access"] == ACCESS_COMPONENT_CAP  # 3 x 12 = 36 -> capped at 30
    assert points["signal"] == 60  # 55 + 5 (single alert)


def test_blast_component_privileged_plus_role() -> None:
    alerts = [alert("D2_new_device_signin", "high", 0.9, "evt-a")]
    access = {"reachable_sensitive": [], "privileged": True, "directory_role": True}
    result = score_identity("usr-x", alerts, access)
    points = {c["name"]: c["points"] for c in result["components"]}
    assert points["blast"] == BLAST_COMPONENT_CAP
    assert result["score"] == 40 + 5 + 15  # 60
    assert result["severity_band"] == "medium"  # 40-69 band


def test_severity_band_mapping() -> None:
    none = score_identity("usr-x", [], {"reachable_sensitive": [], "privileged": False, "directory_role": False})
    assert none["score"] == 0 and none["severity_band"] == "none"

    low = score_identity(
        "usr-x",
        [alert("D2_new_device_signin", "low", 0.9, "evt-a")],
        {"reachable_sensitive": [], "privileged": False, "directory_role": False},
    )
    assert low["score"] == 10 + 5 and low["severity_band"] == "low"

    high = score_identity(
        "usr-x",
        [alert("D1_mfa_fatigue", "critical", 0.95, "evt-a")],
        {"reachable_sensitive": ["res-hr-portal"], "privileged": False, "directory_role": False},
    )
    assert high["score"] == 60 + 12 and high["severity_band"] == "high"  # 72

    critical = score_identity(
        "usr-x",
        [
            alert("D1_mfa_fatigue", "critical", 0.95, "evt-a"),
            alert("D3_impossible_travel", "high", 0.85, "evt-b"),
            alert("D5_role_assignment_anomaly", "high", 0.9, "evt-c"),
        ],
        {"reachable_sensitive": ["res-ehr-database"], "privileged": True, "directory_role": True},
    )
    # 55 + 15 + 12 + 15 = 97
    assert critical["score"] == 97 and critical["severity_band"] == "critical"


def test_score_is_int_and_unknown_severity_is_tolerated() -> None:
    weird = [alert("D_unknown", "catastrophic", 0.9, "evt-a")]  # severity outside the enum
    result = score_identity("usr-x", weird, {"reachable_sensitive": [], "privileged": False, "directory_role": False})
    assert isinstance(result["score"], int)
    assert result["severity_band"] == "low"  # unknown severity falls back to low (10) + bonus 5
