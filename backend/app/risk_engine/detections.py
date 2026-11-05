"""Behavioral detectors D1–D6 for SPECTER X (CONTRACTS §3, detection contract).

Every detector is a PURE function::

    detect(events: list[dict], ctx: dict) -> list[dict]   # Alert dicts

No DB, no I/O, no global state. Sorting by ``(timestamp, event_id)`` makes
tie-breaking deterministic; running any detector twice over identical inputs
yields identical output (unit-tested).

Detector context (``ctx``)
-------------------------
::

    {
        # identity metadata (required keys per identity are tolerated absent):
        "identities": {
            "usr-...": {"privileged": bool, "kind": "user" | "service_account"},
        },
        # city coordinates for D3 distance math:
        "cities": {"San Antonio": (29.42, -98.49), ...},
        # optional, used by D5 to decide "privileged group":
        "privileged_groups": ["grp-it-admins", ...],
    }

Missing keys are tolerated: unknown identities default to non-privileged
users; a city missing from ``cities`` suppresses D3 math for that pair.

Batch semantics (documented FP boundary)
----------------------------------------
Detectors see an evaluation batch (a scenario file or a time-boxed window),
so "never seen before" is evaluated *within the batch*:

* D2: a device is "new" for an identity when no OTHER sign-in event of that
  identity in the batch carries the same ``device_id`` (first-and-only
  sighting). An identity that re-uses a device anywhere in the batch has
  established it. In a streaming deployment the DB supplies history; the
  batch is the history here.
* D6: a service account IP is "never-seen" when no PRIOR event (any type)
  of that identity in the batch carries the same ``ip``.

Alert shape (CONTRACTS §3)::

    {"detection_id", "severity", "confidence", "identity_id",
     "reason", "event_refs", "false_positive_notes"}
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Callable
from datetime import datetime

# ---------------------------------------------------------------- constants

D1_MFA_FATIGUE = "D1_mfa_fatigue"
D2_NEW_DEVICE = "D2_new_device_signin"
D3_IMPOSSIBLE_TRAVEL = "D3_impossible_travel"
D4_RISKY_OAUTH_CONSENT = "D4_risky_oauth_consent"
D5_ROLE_ASSIGNMENT_ANOMALY = "D5_role_assignment_anomaly"
D6_SERVICE_ACCOUNT_INTERACTIVE = "D6_service_account_interactive"

#: D1: denials + following success must fall inside this window.
D1_WINDOW_SECONDS = 30 * 60
#: D1: minimum denials before the success for a fatigue burst.
D1_MIN_DENIALS = 5
#: D3: implied speed threshold (km/h) between successive successful sign-ins.
D3_MIN_SPEED_KMH = 500.0
#: D3: ASN types whose GeoIP city attribution is too uncertain — pairs on
#: these are suppressed entirely (the documented GeoIP-uncertainty FP rule).
D3_SUPPRESS_ASN_TYPES = {"vpn", "mobile"}
#: D4: scopes that grant sweeping write/directory power (CONTRACTS §3).
D4_HIGH_RISK_SCOPES = {
    "Files.ReadWrite.All",
    "Mail.ReadWrite",
    "RoleManagement.ReadWrite.Directory",
}
#: D5: +/- minutes around any prior grantor activity that counts as
#: "inside the grantor's normal hours".
D5_NORMAL_HOURS_TOLERANCE_MIN = 120

Detector = Callable[[list[dict], dict], list[dict]]

#: CONTRACTS §3 — `risk_engine.detections.DETECTIONS` is this list.
DETECTIONS: list[Detector] = []  # populated by the decorators below


# ---------------------------------------------------------------- helpers


def _parse_ts(raw: str) -> datetime:
    """Parse an RFC3339 UTC timestamp. Trailing 'Z' -> '+00:00'."""
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def _attrs(event: dict) -> dict:
    return event.get("attributes") or {}


def _sorted_events(events: list[dict]) -> list[dict]:
    """Deterministic chronological order (ties broken by event_id)."""
    return sorted(events, key=lambda e: (e.get("timestamp", ""), e.get("event_id", "")))


def _ident_meta(ctx: dict, identity_id: str) -> dict:
    """Identity metadata with safe defaults (non-privileged user)."""
    meta = (ctx.get("identities") or {}).get(identity_id) or {}
    return {
        "privileged": bool(meta.get("privileged", False)),
        "kind": meta.get("kind", "user"),
    }


def _alert(
    detection_id: str,
    severity: str,
    confidence: float,
    identity_id: str,
    reason: str,
    event_refs: list[str],
    false_positive_notes: str,
) -> dict:
    """Build one contract-shaped Alert dict. Refs are de-duplicated, order kept."""
    seen: set[str] = set()
    refs = [r for r in event_refs if not (r in seen or seen.add(r))]
    return {
        "detection_id": detection_id,
        "severity": severity,
        "confidence": confidence,
        "identity_id": identity_id,
        "reason": reason,
        "event_refs": refs,
        "false_positive_notes": false_positive_notes,
    }


def _haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    """Great-circle distance between (lat, lon) pairs, in km."""
    lat1, lon1 = math.radians(a[0]), math.radians(a[1])
    lat2, lon2 = math.radians(b[0]), math.radians(b[1])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2.0) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2.0) ** 2
    return 2.0 * 6371.0088 * math.asin(math.sqrt(h))


def _detector(detection_id: str) -> Callable[[Detector], Detector]:
    """Register the wrapped callable in DETECTIONS (declaration order = D1..D6)."""

    def _wrap(fn: Detector) -> Detector:
        fn.detection_id = detection_id  # type: ignore[attr-defined]
        DETECTIONS.append(fn)
        return fn

    return _wrap


# ---------------------------------------------------------------- D1


def _successful_signins(events: list[dict]) -> list[dict]:
    return [e for e in events if e.get("type") == "signin" and _attrs(e).get("result") == "success"]


@_detector(D1_MFA_FATIGUE)
def d1_mfa_fatigue(events: list[dict], ctx: dict) -> list[dict]:
    """MFA fatigue/push-bombing: >= D1_MIN_DENIALS `mfa_denied` events for an
    identity, then a `signin` SUCCESS for the same identity within
    D1_WINDOW_SECONDS of (the last) denial.

    Window logic: for every successful sign-in, look back 30 minutes and
    collect that identity's denials; >= 5 denials in the lookback window
    means the success directly followed a denial storm.
    """
    del ctx  # D1 needs no identity metadata
    by_ident: dict[str, list[dict]] = defaultdict(list)
    for e in _sorted_events(events):
        if e.get("type") in ("signin", "mfa_denied"):
            by_ident[e.get("identity_id", "")].append(e)

    alerts: list[dict] = []
    for iid in sorted(by_ident):
        evs = by_ident[iid]
        denials = [e for e in evs if e.get("type") == "mfa_denied"]
        if len(denials) < D1_MIN_DENIALS:
            continue
        denial_ts = [_parse_ts(e["timestamp"]) for e in denials]
        for succ in _successful_signins(evs):
            succ_ts = _parse_ts(succ["timestamp"])
            window = [
                e
                for e, t in zip(denials, denial_ts)
                if 0 <= (succ_ts - t).total_seconds() <= D1_WINDOW_SECONDS
            ]
            if len(window) < D1_MIN_DENIALS:
                continue
            first, last = window[0], window[-1]
            span_min = int(
                (_parse_ts(last["timestamp"]) - _parse_ts(first["timestamp"])).total_seconds() // 60
            )
            ip = _attrs(last).get("ip") or _attrs(succ).get("ip") or "unknown"
            hhmm = succ_ts.strftime("%H:%M")
            alerts.append(
                _alert(
                    D1_MFA_FATIGUE,
                    "critical",
                    0.95,
                    iid,
                    (
                        f"{len(window)} MFA denials in {span_min} minutes from {ip} "
                        f"followed by success at {hhmm} UTC"
                    ),
                    [e["event_id"] for e in window] + [succ["event_id"]],
                    (
                        "Fires wrongly when a user legitimately denies repeated prompts and then "
                        "completes a delayed real login within 30 min (lost phone, token "
                        "re-enrollment, shared kiosk). Push fatigue alone without a following "
                        "success is not alerted."
                    ),
                )
            )
    return alerts


# ---------------------------------------------------------------- D2


@_detector(D2_NEW_DEVICE)
def d2_new_device_signin(events: list[dict], ctx: dict) -> list[dict]:
    """Successful sign-in from a device never seen before for that identity,
    AND (identity privileged OR asn_type == "datacenter") — the CONTRACTS §3
    refinement.

    FP rule (contract text): a new device on vpn/residential/mobile ASN alone
    is NOT alert-worthy — VPN/mobile IP churn and hardware refresh are normal.
    Only privileged identities (any ASN) or datacenter ASN promote a
    first-seen device to an alert.
    """
    # Batch device universe: (identity, device_id) -> number of sign-in events.
    signin_device_counts: Counter[tuple[str, str]] = Counter()
    for e in events:
        if e.get("type") != "signin":
            continue
        dev = _attrs(e).get("device_id")
        if dev:
            signin_device_counts[(e.get("identity_id", ""), str(dev))] += 1

    alerts: list[dict] = []
    for e in _sorted_events(events):
        if e.get("type") != "signin":
            continue
        attrs = _attrs(e)
        if attrs.get("result") != "success":
            continue
        iid = e.get("identity_id", "")
        dev = attrs.get("device_id")
        if not dev:
            continue
        # "Never seen before": no OTHER sign-in of this identity in the batch
        # carries this device_id (see module docstring, batch semantics).
        if signin_device_counts[(iid, str(dev))] > 1:
            continue
        meta = _ident_meta(ctx, iid)
        asn = attrs.get("asn_type", "unknown")
        if not (meta["privileged"] or asn == "datacenter"):
            continue  # documented FP rule: new device + ordinary ASN is normal churn
        privileged = meta["privileged"]
        reason = (
            f"Successful signin for {iid} from never-seen device {dev} at "
            f"{attrs.get('ip', 'unknown ip')} ({attrs.get('city', 'unknown city')} "
            f"{attrs.get('country', '')}, asn={asn}) at "
            f"{_parse_ts(e['timestamp']).strftime('%H:%M')} UTC; "
            f"privileged={str(privileged).lower()}"
            + ("" if privileged else ", datacenter ASN")
        )
        alerts.append(
            _alert(
                D2_NEW_DEVICE,
                "high" if privileged else "medium",
                0.9 if privileged else 0.8,
                iid,
                reason,
                [e["event_id"]],
                (
                    "Fires wrongly when a privileged user legitimately enrolls a new laptop/phone, "
                    "or when the analyzed batch lacks the identity's sign-in history (first batch "
                    "after provisioning). New devices on vpn/residential/mobile ASN for "
                    "non-privileged identities are never alerted (VPN/mobile IP churn is normal)."
                ),
            )
        )
    return alerts


# ---------------------------------------------------------------- D3


@_detector(D3_IMPOSSIBLE_TRAVEL)
def d3_impossible_travel(events: list[dict], ctx: dict) -> list[dict]:
    """Two consecutive SUCCESSFUL sign-ins for the same identity whose city
    distance implies >= D3_MIN_SPEED_KMH travel.

    GeoIP-uncertainty FP rule: the pair is SUPPRESSED ENTIRELY (skipped, not
    downgraded) when either event's asn_type is "vpn" or "mobile" — commercial
    VPN egress and carrier-grade NAT routinely misattribute the city a sign-in
    geolocates to, so the implied-speed math is meaningless for those ASNs.
    Pairs with a city missing from ctx["cities"] are also skipped (no math).
    """
    cities: dict[str, tuple[float, float]] = {k: tuple(v) for k, v in (ctx.get("cities") or {}).items()}
    by_ident: dict[str, list[dict]] = defaultdict(list)
    for e in _sorted_events(events):
        if e.get("type") == "signin" and _attrs(e).get("result") == "success" and _attrs(e).get("city"):
            by_ident[e.get("identity_id", "")].append(e)

    alerts: list[dict] = []
    for iid in sorted(by_ident):
        evs = by_ident[iid]
        for prev, cur in zip(evs, evs[1:]):
            a_prev, a_cur = _attrs(prev), _attrs(cur)
            if a_prev.get("asn_type") in D3_SUPPRESS_ASN_TYPES or a_cur.get("asn_type") in D3_SUPPRESS_ASN_TYPES:
                continue  # GeoIP-uncertainty FP rule — skip the pair entirely
            c1, c2 = a_prev["city"], a_cur["city"]
            if c1 not in cities or c2 not in cities:
                continue  # unknown coordinates -> no distance math, no alert
            dt_hours = (_parse_ts(cur["timestamp"]) - _parse_ts(prev["timestamp"])).total_seconds() / 3600.0
            if dt_hours <= 0:
                continue
            dist_km = _haversine_km(cities[c1], cities[c2])
            if dist_km <= 0:
                continue
            speed = dist_km / dt_hours
            if speed < D3_MIN_SPEED_KMH:
                continue
            minutes = int(dt_hours * 60)
            alerts.append(
                _alert(
                    D3_IMPOSSIBLE_TRAVEL,
                    "high",
                    0.85,
                    iid,
                    (
                        f"Impossible travel for {iid}: {c1} -> {c2}, {int(round(dist_km))} km in "
                        f"{minutes} minutes ({int(round(speed))} km/h implied, threshold "
                        f"{int(D3_MIN_SPEED_KMH)} km/h)"
                    ),
                    [prev["event_id"], cur["event_id"]],
                    (
                        "GeoIP-uncertainty FP rule: pairs on vpn/mobile ASN are suppressed entirely "
                        "because VPN egress and carrier-grade NAT misattribute city-level origin. "
                        "May still fire wrongly on legitimate multi-leg trips with back-to-back "
                        "quick logins, or when the city coordinate table is a coarse approximation."
                    ),
                )
            )
    return alerts


# ---------------------------------------------------------------- D4


@_detector(D4_RISKY_OAUTH_CONSENT)
def d4_risky_oauth_consent(events: list[dict], ctx: dict) -> list[dict]:
    """`consent_granted` whose scopes intersect the high-privilege set
    {Files.ReadWrite.All, Mail.ReadWrite, RoleManagement.ReadWrite.Directory}
    where the app lacks `verified: true`."""
    del ctx
    alerts: list[dict] = []
    for e in _sorted_events(events):
        if e.get("type") != "consent_granted":
            continue
        attrs = _attrs(e)
        scopes = attrs.get("scopes") or []
        risky = sorted(set(scopes) & D4_HIGH_RISK_SCOPES)
        if not risky:
            continue
        if attrs.get("verified") is True:
            continue  # verified publisher + (scope risk gated by consent flow) -> control
        alerts.append(
            _alert(
                D4_RISKY_OAUTH_CONSENT,
                "high",
                0.9,
                e.get("identity_id", ""),
                (
                    f"Consent granted to unverified app {attrs.get('app_id', 'unknown app')} "
                    f"with high-privilege scope(s): {', '.join(risky)}"
                ),
                [e["event_id"]],
                (
                    "Fires wrongly when an organization deliberately tolerates unverified internal "
                    "first-party apps with write scopes, or when the telemetry omits the verified "
                    "flag for an actually-verified app (missing flag is treated as unverified — "
                    "conservative by design)."
                ),
            )
        )
    return alerts


# ---------------------------------------------------------------- D5


@_detector(D5_ROLE_ASSIGNMENT_ANOMALY)
def d5_role_assignment_anomaly(events: list[dict], ctx: dict) -> list[dict]:
    """`role_assigned` to a PRIVILEGED group where the grantor (the event's
    identity_id, i.e. the actor) lacks an admin directory role OR acts outside
    their normal hours (no prior activity within +/-2h time-of-day).

    The alert is attached to the TARGET identity (``attributes.target_id``),
    severity high when the target group is privileged. Events lacking
    ``grantor_has_admin: true`` are treated as lacking admin evidence
    (conservative). A grantor with zero prior activity in the batch has no
    established normal hours -> the hours condition holds.
    """
    privileged_groups = set(ctx.get("privileged_groups") or [])
    prior_by_grantor: dict[str, list[datetime]] = defaultdict(list)
    alerts: list[dict] = []
    for e in _sorted_events(events):
        iid = e.get("identity_id", "")
        if e.get("type") == "role_assigned":
            attrs = _attrs(e)
            role = attrs.get("role")
            if privileged_groups and role not in privileged_groups:
                continue  # only privileged-group assignments are in scope
            grantor_has_admin = attrs.get("grantor_has_admin") is True
            assigned_ts = _parse_ts(e["timestamp"])
            tod = assigned_ts.hour * 60 + assigned_ts.minute
            within_normal_hours = any(
                abs(tod - (t.hour * 60 + t.minute)) <= D5_NORMAL_HOURS_TOLERANCE_MIN
                for t in prior_by_grantor.get(iid, [])
            )
            if grantor_has_admin and within_normal_hours:
                continue  # admin acting during their normal hours -> control (no alert)
            lacks_admin = not grantor_has_admin
            target = attrs.get("target_id") or iid
            is_privileged_group = bool(role in privileged_groups)
            why = []
            if lacks_admin:
                why.append(f"grantor {iid} lacks admin directory role")
            if not within_normal_hours:
                why.append(
                    "outside grantor's normal hours (no prior activity within ±2h)"
                    if prior_by_grantor.get(iid)
                    else "no prior activity for grantor in batch -> no established normal hours"
                )
            alerts.append(
                _alert(
                    D5_ROLE_ASSIGNMENT_ANOMALY,
                    "high" if is_privileged_group else "medium",
                    0.9 if is_privileged_group else 0.7,
                    target,  # attach to the TARGET identity
                    (
                        f"Role {role} assigned to {target} by {iid} at "
                        f"{assigned_ts.strftime('%H:%M')} UTC: " + "; ".join(why)
                    ),
                    [e["event_id"]],
                    (
                        "Fires wrongly for legitimate break-glass/delegated administration by "
                        "grantors whose admin flag or activity history is absent from the analyzed "
                        "batch (missing grantor_has_admin is treated as lacking admin evidence)."
                    ),
                )
            )
        ts = _parse_ts(e["timestamp"])
        prior_by_grantor[iid].append(ts)  # any event type counts as grantor activity
    return alerts


# ---------------------------------------------------------------- D6


@_detector(D6_SERVICE_ACCOUNT_INTERACTIVE)
def d6_service_account_interactive(events: list[dict], ctx: dict) -> list[dict]:
    """Identity with ctx kind=service_account performing an INTERACTIVE
    successful sign-in from an IP never seen for that identity before
    (prior-only: earlier events in the batch, any type). Service accounts are
    expected to run non-interactive batch jobs from fixed egress IPs; an
    interactive human-style login from fresh infrastructure is takeover-class.
    """
    seen_ips: dict[str, set[str]] = defaultdict(set)
    alerts: list[dict] = []
    for e in _sorted_events(events):
        iid = e.get("identity_id", "")
        attrs = _attrs(e)
        if (
            e.get("type") == "signin"
            and attrs.get("result") == "success"
            and attrs.get("interactive") is not False  # explicit False = batch/non-interactive flow
            and _ident_meta(ctx, iid)["kind"] == "service_account"
        ):
            ip = attrs.get("ip")
            if ip and ip not in seen_ips.get(iid, set()):
                alerts.append(
                    _alert(
                        D6_SERVICE_ACCOUNT_INTERACTIVE,
                        "high",
                        0.85,
                        iid,
                        (
                            f"Service account {iid} (kind=service_account) performed interactive "
                            f"signin from never-seen IP {ip} at "
                            f"{_parse_ts(e['timestamp']).strftime('%H:%M')} UTC "
                            f"(asn={attrs.get('asn_type', 'unknown')}, "
                            f"{attrs.get('city', 'unknown city')} {attrs.get('country', '')})"
                        ),
                        [e["event_id"]],
                        (
                            "Fires wrongly when an operator intentionally uses a service account "
                            "interactively (break-glass console login) or when the service "
                            "account's regular egress IPs are absent from the analyzed batch."
                        ),
                    )
                )
        ip = attrs.get("ip")
        if ip:
            seen_ips[iid].add(ip)  # recorded AFTER the check => strictly-prior semantics
    return alerts


# ---------------------------------------------------------------- driver


def run_all_detections(events: list[dict], ctx: dict | None = None) -> list[dict]:
    """Run every detector in DETECTIONS over ``events`` and return the merged
    alert list in a deterministic order (identity_id, detection_id, first ref).
    """
    ctx = ctx or {}
    alerts: list[dict] = []
    for detector in DETECTIONS:
        alerts.extend(detector(events, ctx))
    alerts.sort(key=lambda a: (a["identity_id"], a["detection_id"], a["event_refs"][0]))
    return alerts
