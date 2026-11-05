"""Normalizers: vendor-native records -> canonical event (CONTRACTS §1).

Two small, honest adapters for the documented subset. Unknown vendor records
return None — callers must reject rather than guess. Vendor event ids are
kept verbatim as the canonical event_id so re-fetched pages dedupe on ingest.
"""
from __future__ import annotations


def normalize_entra(raw: dict) -> dict | None:
    """Microsoft Entra ID sign-in log shape -> canonical.

    Recognizes signInLogs records with activityDateTime, status.errorCode,
    location, deviceDetail, mfaDetail.
    """
    if not isinstance(raw, dict) or "id" not in raw or "activityDateTime" not in raw:
        return None
    # The vendor's event id IS the idempotency key — reusing it verbatim keeps
    # re-fetched Entra pages duplicate-free on ingest.
    event_id = raw["id"]
    err = int((raw.get("status") or {}).get("errorCode", 0))
    device = raw.get("deviceDetail") or {}
    loc = raw.get("location") or {}
    if err == 500121:  # MFA denied by user
        etype = "mfa_denied"
    elif err:
        etype = "signinfailure"
    else:
        etype = "signin"
    return {
        "event_id": event_id, "source": "entra", "type": etype,
        "timestamp": raw["activityDateTime"],
        "identity_id": raw.get("userId") or raw.get("userPrincipalName") or "",
        "attributes": {
            "ip": (raw.get("ipAddress") or raw.get("ipAddressFromResourceProvider") or ""),
            "device_id": device.get("deviceId") or "unknown-device",
            "city": loc.get("city") or "", "country": loc.get("countryOrRegion") or "",
            "mfa_method": (raw.get("mfaDetail") or {}).get("authMethod") or "",
            "result": "denied" if err else "success",
        },
        "raw": raw,
    }


def normalize_cloudtrail(raw: dict) -> dict | None:
    """CloudTrail Record shape -> canonical api_call."""
    if not isinstance(raw, dict) or "eventID" not in raw or "eventTime" not in raw:
        return None
    return {
        "event_id": raw["eventID"], "source": "cloudtrail", "type": "api_call",
        "timestamp": raw["eventTime"],
        "identity_id": raw.get("userIdentity", {}).get("principalId", ""),
        "attributes": {
            "ip": raw.get("sourceIPAddress", ""),
            "resource_id": ((raw.get("resources") or [{}])[0].get("arn", "")),
            "operation": raw.get("eventName", ""),
        },
        "raw": raw,
    }


NORMALIZERS = {"entra": normalize_entra, "cloudtrail": normalize_cloudtrail}
