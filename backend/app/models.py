"""SQLAlchemy models — SPECTER X persistence layer.

SQLite by default, Postgres via DATABASE_URL. JSON columns are portable.
Every table that stores security findings keeps event references so that
100% traceability (findings -> event ids) is enforceable by tests.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, DateTime, Float, String, Text,
                        create_engine)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


def _default_db_url() -> str:
    return os.environ.get("DATABASE_URL", "sqlite:///./specter.db")


engine = create_engine(_default_db_url(), connect_args={"check_same_thread": False} if _default_db_url().startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Identity(Base):
    __tablename__ = "identities"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # usr-*/svc-*
    display_name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(24), default="user")  # user|service_account
    department: Mapped[str] = mapped_column(String(64), default="")
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Resource(Base):
    __tablename__ = "resources"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # res-*
    label: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(32), default="cloud_resource")
    sensitivity: Mapped[str] = mapped_column(String(16), default="internal")  # sensitive|internal|public


class Grant(Base):
    """One authorization relationship. `kind` uses CONTRACTS §2 vocabulary."""
    __tablename__ = "grants"
    grant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))  # IDENTITY_POLICY_ALLOW|IDENTITY_POLICY_DENY|RESOURCE_POLICY|TRUST_ASSUME|GROUP_MEMBER|APP_CONSENT|DIRECTORY_ROLE
    from_id: Mapped[str] = mapped_column(String(64))
    to_id: Mapped[str] = mapped_column(String(64))  # group/role/app/resource depending on kind
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    scopes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    conditions: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # {ip_in, time_window, asn_type_in}
    verified: Mapped[bool] = mapped_column(Boolean, default=True)  # for APP_CONSENT: publisher verified
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Event(Base):
    __tablename__ = "events"
    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)  # idempotency key
    source: Mapped[str] = mapped_column(String(16))  # entra|cloudtrail|oauth
    type: Mapped[str] = mapped_column(String(32))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    identity_id: Mapped[str] = mapped_column(String(64), index=True)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)


class Alert(Base):
    __tablename__ = "alerts"
    alert_id: Mapped[str] = mapped_column(String(64), primary_key=True)  # alr-*
    detection_id: Mapped[str] = mapped_column(String(48), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)  # critical|high|medium|low
    confidence: Mapped[float] = mapped_column(Float)
    identity_id: Mapped[str] = mapped_column(String(64), index=True)
    reason: Mapped[str] = mapped_column(Text)
    event_refs: Mapped[list] = mapped_column(JSON)  # >=1 event_id, 100% traceability
    false_positive_notes: Mapped[str] = mapped_column(Text, default="")
    case_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Case(Base):
    __tablename__ = "cases"
    case_id: Mapped[str] = mapped_column(String(64), primary_key=True)  # case-*
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(16))
    identity_id: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(24), default="open")  # open|contained|closed
    conclusion: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ResponseAudit(Base):
    """Simulated response actions. Demo-only, never calls external systems."""
    __tablename__ = "response_audit"
    audit_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    action: Mapped[str] = mapped_column(String(32))  # consent_revoke|account_disable|session_revoke
    target_id: Mapped[str] = mapped_column(String(64))
    actor_role: Mapped[str] = mapped_column(String(24))
    simulated: Mapped[bool] = mapped_column(Boolean, default=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def init_db() -> None:
    Base.metadata.create_all(engine)
