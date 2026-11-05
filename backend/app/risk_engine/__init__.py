"""SPECTER X risk engine — behavioral detections + deterministic risk scoring.

Track B package. Public surface (CONTRACTS §3 / §4):

    from app.risk_engine import DETECTIONS, run_all_detections, score_identity

* ``DETECTIONS``            — list of pure detector callables ``(events, ctx) -> list[Alert-dict]``
* ``run_all_detections``    — convenience: run every detector, merge, deterministic order
* ``score_identity``        — deterministic, explainable 0-100 risk score per identity

No third-party dependencies; no DB access (persistence layers wrap these
pure functions).
"""
from __future__ import annotations

from .detections import DETECTIONS, run_all_detections
from .scoring import score_identity

__all__ = ["DETECTIONS", "run_all_detections", "score_identity"]
__version__ = "1.0.0"
