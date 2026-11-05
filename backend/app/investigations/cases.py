"""Case builder: correlate alerts + events into an investigation case.

Correlation rule (documented in docs/detection-methodology.md): alerts for
the same identity within a 6-hour window form one case; the case timeline
merges the scenario events with the alerts, time-sorted, every item carrying
its event_id/alert_id so findings stay 100% traceable.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone


def _dt_str(value) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value or "")


def _ts(e: dict) -> datetime:
    return datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))


def correlate(alerts: list[dict], events: list[dict], identity_meta: dict | None = None) -> list[dict]:
    """Group alerts into cases; attach timelines. Pure function."""
    cases: list[dict] = []
    by_identity: dict[str, list[dict]] = {}
    for a in alerts:
        by_identity.setdefault(a["identity_id"], []).append(a)

    for identity_id, id_alerts in by_identity.items():
        id_alerts = sorted(id_alerts, key=lambda a: a.get("created_at") or a.get("first_seen") or "")
        ref_events = {r for a in id_alerts for r in a.get("event_refs", [])}
        ev_index = {e["event_id"]: e for e in events}
        alert_anchor = {a["alert_id"]: _ts(ev_index[a["event_refs"][0]]) if a.get("event_refs") and a["event_refs"][0] in ev_index else None
                        for a in id_alerts}
        window_events = [ev_index[r] for r in ref_events if r in ev_index]
        # widen the window: identity events between first ref and last ref (+30 min)
        if window_events:
            lo = min(_ts(e) for e in window_events) - timedelta(minutes=30)
            hi = max(_ts(e) for e in window_events) + timedelta(minutes=30)
            per_id = [e for e in events
                      if e["identity_id"] == identity_id and lo <= _ts(e) <= hi]
            merged = {e["event_id"]: e for e in window_events + per_id}
            window_events = sorted(merged.values(), key=_ts)

        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        worst = min((a["severity"] for a in id_alerts), key=lambda s: severity_rank[s])
        meta = (identity_meta or {}).get(identity_id, {})
        detections = sorted({a["detection_id"] for a in id_alerts})
        cases.append({
            "case_id": "case-" + hashlib.md5(identity_id.encode()).hexdigest()[:12],
            "title": f"Identity compromise — {meta.get('display_name', identity_id)}",
            "severity": worst,
            "identity_id": identity_id,
            "status": "open",
            "detections": detections,
            "alert_ids": [a["alert_id"] for a in id_alerts],
            "conclusion": (
                f"{len(id_alerts)} correlated signal(s) from {len(detections)} detection(s) "
                f"({', '.join(detections)}). Investigate consent grants and active sessions, "
                f"then revoke after approval."
            ),
            "timeline": (
                [{"kind": "event", "event_id": e["event_id"], "timestamp": e["timestamp"],
                  "type": e["type"], "source": e["source"], "summary": _event_summary(e)}
                 for e in window_events]
                + [{"kind": "alert", "alert_id": a["alert_id"], "detection_id": a["detection_id"],
                    "severity": a["severity"], "confidence": a["confidence"],
                    "timestamp": (_dt_str(alert_anchor.get(a["alert_id"])) or _dt_str(a.get("created_at"))),
                    "summary": a["reason"],
                    "event_refs": a.get("event_refs", [])}
                   for a in id_alerts]
            ),
        })
        cases[-1]["timeline"].sort(key=lambda t: t["timestamp"] or "9999")
    return cases


def _event_summary(e: dict) -> str:
    a = e.get("attributes", {})
    bits = [f"{e['source']}:{e['type']}"]
    for key in ("ip", "device_id", "city", "result", "app_id", "resource_id", "operation"):
        if a.get(key):
            bits.append(f"{key}={a[key]}")
    if a.get("scopes"):
        bits.append("scopes=" + ",".join(a["scopes"]))
    return " ".join(bits)
