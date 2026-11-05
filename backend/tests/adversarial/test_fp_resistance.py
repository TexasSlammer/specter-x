"""Adversarial FP-resistance tests: crafted benign-but-suspicious-looking
sequences that a naive detector would alert on. SPECTER X must stay silent.
"""
from __future__ import annotations

from app.risk_engine import run_all_detections

CTX = {"identities": {
    "usr-vpn-user": {"privileged": False, "kind": "user"},
    "usr-admin-ok": {"privileged": True, "kind": "user"},
    "svc-nightly": {"privileged": False, "kind": "service_account"},
    "usr-clin": {"privileged": False, "kind": "user"},
}, "cities": {"San Antonio": (29.42, -98.49), "Berlin": (52.52, 13.40)},
    "privileged_groups": ["grp-it-admins"]}


def ev(eid, ts_, type_, ident, **attrs):
    return {"event_id": eid, "source": "entra", "type": type_, "timestamp": ts_,
            "identity_id": ident, "attributes": attrs, "raw": {}}


def test_impossible_travel_via_vpn_is_suppressed():
    """User flies SA -> Berlin; both hops on VPN/mobile ASN = GeoIP uncertainty, no alert."""
    events = [
        ev("a1", "2026-11-02T09:00:00Z", "signin", "usr-vpn-user",
           ip="1.2.3.4", device_id="d1", city="San Antonio", asn_type="vpn", result="success"),
        ev("a2", "2026-11-02T12:00:00Z", "signin", "usr-vpn-user",
           ip="5.6.7.8", device_id="d1", city="Berlin", asn_type="vpn", result="success"),
    ]
    assert run_all_detections(events, CTX) == []


def test_verified_app_consent_is_not_risky():
    events = [ev("b1", "2026-11-02T11:00:00Z", "consent_granted", "usr-clin",
                 app_id="app-mail-sync", scopes=["Mail.Read"], verified=True)]
    assert run_all_detections(events, CTX) == []


def test_admin_role_activation_in_hours_is_normal():
    events = [
        ev("c0", "2026-10-27T10:00:00Z", "signin", "usr-admin-ok",
           ip="1.2.3.4", device_id="d9", city="San Antonio", asn_type="residential", result="success"),
        ev("c1", "2026-10-30T10:00:00Z", "signin", "usr-admin-ok",
           ip="1.2.3.4", device_id="d9", city="San Antonio", asn_type="residential", result="success"),
        ev("c2", "2026-11-02T10:05:00Z", "role_assigned", "usr-admin-ok",
           role="grp-it-admins", target_id="usr-clin", grantor_has_admin=True),
    ]
    assert run_all_detections(events, CTX) == []


def test_service_account_known_ip_batch_is_normal():
    events = [ev("d1", "2026-11-02T01:15:00Z", "api_call", "svc-nightly",
                 ip="198.51.100.9", resource_id="res-backup-vault", operation="snapshot")]
    assert run_all_detections(events, CTX) == []


def test_consent_without_scope_mapping_does_not_fake_reachability():
    """A consent to a low-scope app must not be treated as high-priv access."""
    events = [ev("e1", "2026-11-02T11:00:00Z", "consent_granted", "usr-clin",
                 app_id="app-mail-sync", scopes=["Mail.Read"], verified=False)]
    alerts = run_all_detections(events, CTX)
    assert all(a["detection_id"] != "D4_risky_oauth_consent" for a in alerts)
