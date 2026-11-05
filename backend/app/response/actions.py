"""Response actions — SIMULATION ONLY (CONTRACTS §5/Component F).

The public demo has no connection to any real tenant. Every action writes an
audit row and returns simulated=True. Real-tenant wiring (approval gates,
least-privilege API credentials, dry-run) is documented in docs/limitations.md
and deliberately out of scope for the prototype.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import new_audit_id
from ..models import Grant, Identity, ResponseAudit


def consent_revoke(db: Session, identity_id: str, app_id: str | None, actor_role: str) -> dict:
    target = app_id or _first_consented_app(db, identity_id) or identity_id
    return _audit(db, "consent_revoke", target, actor_role)


def account_disable(db: Session, identity_id: str, actor_role: str) -> dict:
    ident = db.get(Identity, identity_id)
    if ident is not None:
        ident.active = False
        db.commit()
    return _audit(db, "account_disable", identity_id, actor_role)


def session_revoke(db: Session, identity_id: str, actor_role: str) -> dict:
    return _audit(db, "session_revoke", identity_id, actor_role)


def _first_consented_app(db: Session, identity_id: str) -> str | None:
    row = db.execute(
        select(Grant.to_id).where(Grant.kind == "APP_CONSENT", Grant.from_id == identity_id)
    ).first()
    return row[0] if row else None


def _audit(db: Session, action: str, target_id: str, actor_role: str) -> dict:
    row = ResponseAudit(audit_id=new_audit_id(), action=action, target_id=target_id,
                        actor_role=actor_role, simulated=True)
    db.add(row)
    db.commit()
    return {"action": action, "target_id": target_id, "simulated": True,
            "audit_id": row.audit_id, "note": "simulation only — no external system contacted"}
