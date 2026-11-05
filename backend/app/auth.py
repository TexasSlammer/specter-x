"""Token-based demo auth with roles. CONTRACTS §5.

Tokens come from env SPECTER_TOKENS as CSV "token:role" pairs
(default ships analyst + admin demo tokens). This is deliberately simple:
the project's security claim is the RBAC enforcement matrix (401/403
behavior), not a production IdP integration.
"""
from __future__ import annotations

import os
import secrets

from fastapi import Header, HTTPException

DEFAULT_TOKENS = "demo-analyst-token:analyst,demo-admin-token:admin"


def _tokens() -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in os.environ.get("SPECTER_TOKENS", DEFAULT_TOKENS).split(","):
        pair = pair.strip()
        if ":" in pair:
            tok, role = pair.split(":", 1)
            if tok and role in {"analyst", "admin"}:
                out[tok] = role
    return out


def check_token(authorization: str | None = Header(default=None)) -> tuple[str, str]:
    """FastAPI dependency -> (token, role). 401 on missing/unknown token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    role = _tokens().get(token)
    if role is None:
        raise HTTPException(status_code=401, detail="unknown token")
    return token, role


def require_admin(authorization: str | None = Header(default=None)) -> str:
    """Dependency for admin-only endpoints. 401 unknown token, 403 wrong role."""
    _, role = check_token(authorization)
    if role != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    return authorization.removeprefix("Bearer ").strip()  # type: ignore[union-attr]


def new_audit_id() -> str:
    return "aud-" + secrets.token_hex(8)


def new_alert_id() -> str:
    return "alr-" + secrets.token_hex(8)


def new_case_suffix() -> str:
    return secrets.token_hex(4)
