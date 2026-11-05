"""Public path-finding API over the SPECTER X attack graph (Track A, sx-4).

Thin, dependency-free orchestration on top of :mod:`permission_eval`:

* :func:`evaluate_path` — one (identity, resource, ctx) verdict with grant-id
  evidence. This is what the ground-truth harness and ``POST /api/evaluate``
  style flows call.
* :func:`find_reachable_sensitive_resources` — every **sensitive** resource an
  identity can reach under a context, with evidence chains. This feeds the
  risk-scoring ``access_component`` (CONTRACTS §4: 12 points per reachable
  sensitive resource) and the identity-detail API (CONTRACTS §5).

Both are pure functions of the graph — the caller owns graph lifetime.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import networkx as nx

from .graph_builder import NodeKind
from .permission_eval import evaluate_decision

__all__ = ["evaluate_path", "find_reachable_sensitive_resources"]


def evaluate_path(
    graph: nx.DiGraph,
    identity_id: str,
    resource_id: str,
    ctx: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Decide whether ``identity_id`` can reach ``resource_id`` under ``ctx``.

    The contract sketch omitted the graph argument, but this module is pure
    (no DB), so the graph is passed in explicitly; API layers bind it.

    Evaluation order: explicit deny on any subject in the identity's chain
    wins (AWS semantics — a "no" no allow can cancel, reported even when no
    allow exists); then all candidate routes (direct, group/nested-group,
    trust chains, consent delegation, resource policy) must hold their
    conditions under the ctx — one condition-gated route tightens the rest
    (dataset-mandated fail-closed join; rationale in
    ``permission_eval`` module docstring).

    Returns::

        {"reachable": bool,
         "reason": "granted" | "explicit_deny" | "condition_mismatch"
                   | "no_allow_path" | "trust_mismatch",
         "via": "direct" | "group_allow" | "nested_group"
                | "trust_assume_chain" | "consent_delegation"
                | "resource_policy" | None,          # None when denied
         "evidence": [grant_id, ...],   # deny ids / failing ids / winning chain
         "paths": [[grant_id, ...], ...]}  # all valid evidence chains
    """
    return evaluate_decision(graph, identity_id, resource_id, ctx or {})


def find_reachable_sensitive_resources(
    graph: nx.DiGraph,
    identity_id: str,
    ctx: Mapping[str, Any] | None = None,
    *,
    include_denied: bool = False,
) -> list[dict[str, Any]]:
    """List the sensitive resources ``identity_id`` can reach under ``ctx``.

    Attack paths terminate at resources marked ``sensitive`` (CONTRACTS §2);
    internal/public assets are deliberately not reported — they are not the
    crown jewels this tool hunts for.

    Reachable entries carry exactly the API shape::

        {"resource_id": str,
         "paths": [[grant_id, ...], ...],   # evidence chains
         "via": "group_allow" | "trust_assume_chain" | "resource_policy"
                | "consent_delegation" | "direct"}   # API-level vocabulary

    ``nested_group`` is collapsed into ``group_allow`` here: nested membership
    is still a group allow at the API level; the finer attribution stays
    available via :func:`evaluate_path`.

    CONTRACTS §2.4 requires denied paths to be "returned in results, never
    silently dropped". :func:`evaluate_path` always returns them; this sweep
    drops them by default (scoring wants reachability only), but
    ``include_denied=True`` appends one entry per sensitive resource the
    identity could NOT reach::

        {"resource_id": str, "paths": [], "via": None, "reason": str}

    Results are sorted by resource id so downstream scoring is deterministic.
    """
    results: list[dict[str, Any]] = []
    for node, data in sorted(graph.nodes(data=True)):
        if data.get("kind") != NodeKind.RESOURCE or not data.get("sensitive"):
            continue
        verdict = evaluate_decision(graph, identity_id, node, ctx or {})
        if not verdict["reachable"]:
            if include_denied:
                results.append(
                    {
                        "resource_id": node,
                        "paths": [],
                        "via": None,
                        "reason": verdict["reason"],
                    }
                )
            continue
        via = verdict.get("via")
        results.append(
            {
                "resource_id": node,
                "paths": verdict.get("paths", []),
                "via": "group_allow" if via == "nested_group" else via,
            }
        )
    return results
