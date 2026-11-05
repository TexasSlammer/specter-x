"""Deterministic, explainable risk scoring for SPECTER X (CONTRACTS §4).

``score_identity(identity_id, alerts, access_context)`` maps the alert set and
the permission-graph access context of one identity to a 0-100 integer plus a
full audit trail. No ML, no randomness, no wall-clock reads: identical inputs
produce a byte-identical output dict (unit-tested).

Formula
-------
signal_component = max effective severity points
                   (critical 55 / high 40 / medium 25 / low 10)
                 + correlation bonus: 5 per correlated alert, capped at +15
                   (the cap therefore binds at 3+ alerts; this reading is what
                   makes the §4 "cap 15" meaningful for 3-alert scenarios)

Uncertainty rule: an alert with confidence < 0.6 weighs 60% — its severity
points are multiplied by 0.6 (rounded half-to-even to int) and it contributes
3 instead of 5 to the correlation bonus. Every affected number is spelled out
in the explanation strings.

access_component = min(30, 12 × #reachable sensitive resources)
blast_component  = privileged(+10) + directory_role(+5), cap 15

score           = signal + access + blast          (0-100 int)
severity_band   = >=85 critical | >=70 high | >=40 medium | >=1 low | else none
"""
from __future__ import annotations

SEVERITY_POINTS: dict[str, int] = {"critical": 55, "high": 40, "medium": 25, "low": 10}
LOW_CONFIDENCE_THRESHOLD = 0.6
LOW_CONFIDENCE_WEIGHT = 0.6
CORRELATION_BONUS_PER_ALERT = 5
CORRELATION_BONUS_PER_LOW_CONF_ALERT = 3
CORRELATION_BONUS_CAP = 15
ACCESS_POINTS_PER_SENSITIVE_RESOURCE = 12
ACCESS_COMPONENT_CAP = 30
PRIVILEGED_BLAST_POINTS = 10
DIRECTORY_ROLE_BLAST_POINTS = 5
BLAST_COMPONENT_CAP = 15

_BANDS: tuple[tuple[int, str], ...] = (
    (85, "critical"),
    (70, "high"),
    (40, "medium"),
    (1, "low"),
    (0, "none"),
)


def _effective_severity_points(alert: dict) -> int:
    """Severity points with the sub-0.6-confidence uncertainty weighting."""
    points = SEVERITY_POINTS.get(alert.get("severity", ""), 10)
    confidence = float(alert.get("confidence", 1.0))
    if confidence < LOW_CONFIDENCE_THRESHOLD:
        return int(round(points * LOW_CONFIDENCE_WEIGHT))
    return points


def _correlation_bonus(alerts: list[dict]) -> int:
    bonus = 0
    for a in alerts:
        confidence = float(a.get("confidence", 1.0))
        bonus += (
            CORRELATION_BONUS_PER_LOW_CONF_ALERT
            if confidence < LOW_CONFIDENCE_THRESHOLD
            else CORRELATION_BONUS_PER_ALERT
        )
    return min(CORRELATION_BONUS_CAP, bonus)


def _severity_band(score: int) -> str:
    for threshold, band in _BANDS:
        if score >= threshold:
            return band
    return "none"


def score_identity(identity_id: str, alerts: list[dict], access_context: dict | None = None) -> dict:
    """Score one identity deterministically.

    ``access_context`` (from Track A's permission evaluation)::

        {
            "reachable_sensitive": ["res-...", ...],  # sensitive resources reachable
            "privileged": bool,                       # identity is privileged
            "directory_role": bool,                   # identity holds a directory role
        }

    Returns::

        {
            "identity_id": str,
            "score": int,                                  # 0-100
            "severity_band": "critical|high|medium|low|none",
            "components": [{"name", "points", "justification"}, ...],
            "explanation": [str, ...],
        }
    """
    access_context = access_context or {}
    reachable_sensitive: list[str] = list(access_context.get("reachable_sensitive") or [])
    privileged = bool(access_context.get("privileged", False))
    directory_role = bool(access_context.get("directory_role", False))

    # Deterministic alert ordering: strongest first, ties by detection_id then refs.
    ranked = sorted(
        alerts,
        key=lambda a: (
            -_effective_severity_points(a),
            str(a.get("detection_id", "")),
            tuple(str(r) for r in (a.get("event_refs") or [])),
        ),
    )

    # --- signal component -------------------------------------------------
    if ranked:
        top = ranked[0]
        base_points = _effective_severity_points(top)
        bonus = _correlation_bonus(ranked)
        signal = base_points + bonus
        conf = float(top.get("confidence", 1.0))
        weighted_note = (
            f", confidence {conf} < 0.6 so severity weighted x{LOW_CONFIDENCE_WEIGHT}"
            if conf < LOW_CONFIDENCE_THRESHOLD
            else ""
        )
        n_low_conf = sum(1 for a in ranked if float(a.get("confidence", 1.0)) < LOW_CONFIDENCE_THRESHOLD)
        bonus_desc = (
            f"{len(ranked)} correlated alert(s) x{CORRELATION_BONUS_PER_ALERT} pts"
            + (f" ({n_low_conf} below 0.6 confidence x{CORRELATION_BONUS_PER_LOW_CONF_ALERT} pts)" if n_low_conf else "")
            + f", capped at +{CORRELATION_BONUS_CAP}"
        )
        signal_justification = (
            f"max effective severity {base_points} from {top.get('detection_id', '?')} "
            f"(severity={top.get('severity', '?')}, confidence={conf}{weighted_note}) "
            f"+ correlation bonus {bonus} ({bonus_desc})"
        )
    else:
        signal = 0
        signal_justification = "no alerts for this identity"

    # --- access component -------------------------------------------------
    access = min(ACCESS_COMPONENT_CAP, ACCESS_POINTS_PER_SENSITIVE_RESOURCE * len(reachable_sensitive))
    access_justification = (
        f"min({ACCESS_COMPONENT_CAP}, {ACCESS_POINTS_PER_SENSITIVE_RESOURCE} x "
        f"{len(reachable_sensitive)} reachable sensitive resource(s)"
        + (f": {', '.join(sorted(reachable_sensitive))}" if reachable_sensitive else "")
        + ")"
    )

    # --- blast component --------------------------------------------------
    blast = 0
    blast_bits: list[str] = []
    if privileged:
        blast += PRIVILEGED_BLAST_POINTS
        blast_bits.append(f"privileged identity +{PRIVILEGED_BLAST_POINTS}")
    if directory_role:
        blast += DIRECTORY_ROLE_BLAST_POINTS
        blast_bits.append(f"directory role holder +{DIRECTORY_ROLE_BLAST_POINTS}")
    blast = min(BLAST_COMPONENT_CAP, blast)
    blast_justification = "; ".join(blast_bits) if blast_bits else "regular identity, no role"

    score = signal + access + blast

    components = [
        {"name": "signal", "points": signal, "justification": signal_justification},
        {"name": "access", "points": access, "justification": access_justification},
        {"name": "blast", "points": blast, "justification": blast_justification},
    ]

    explanation = [
        f"signal = {base_points if ranked else 0} (max effective severity)"
        + (f" + {bonus} correlation bonus = {signal}" if ranked else ""),
        f"access = {ACCESS_POINTS_PER_SENSITIVE_RESOURCE} pts per reachable sensitive "
        f"resource x {len(reachable_sensitive)} = {ACCESS_POINTS_PER_SENSITIVE_RESOURCE * len(reachable_sensitive)}, "
        f"capped at {ACCESS_COMPONENT_CAP} = {access}",
        f"blast = {blast} ({blast_justification})",
    ]
    low_conf_alerts = [
        f"{a.get('detection_id', '?')} (confidence {float(a.get('confidence', 1.0))})"
        for a in ranked
        if float(a.get("confidence", 1.0)) < LOW_CONFIDENCE_THRESHOLD
    ]
    if low_conf_alerts:
        explanation.append(
            "uncertainty: detections with confidence <0.6 weigh 60% — "
            + ", ".join(low_conf_alerts)
            + f" contribute {int(LOW_CONFIDENCE_WEIGHT * 100)}% of their severity points and 3 instead of 5 to the correlation bonus"
        )
    explanation.append(
        f"score = {signal} + {access} + {blast} = {score}; deterministic rule-based scoring, no ML — same inputs yield identical output"
    )

    return {
        "identity_id": identity_id,
        "score": int(score),
        "severity_band": _severity_band(int(score)),
        "components": components,
        "explanation": explanation,
    }
