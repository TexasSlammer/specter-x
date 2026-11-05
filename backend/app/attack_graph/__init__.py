"""SPECTER X attack-graph package (Track A, task sx-4).

Builds the identity→resource attack graph from org/grant records and answers
reachability questions over it with grant-id evidence.

Public surface::

    from app.attack_graph import (
        build,                              # org dict | grant rows -> nx.DiGraph
        evaluate_path,                      # one (identity, resource, ctx) verdict
        find_reachable_sensitive_resources, # all reachable sensitive resources
        conditions_hold,                    # ctx condition evaluation (ip/time/asn)
        EdgeKind, NodeKind,                 # vocabularies
        MAX_GROUP_DEPTH, MAX_TRUST_HOPS,    # traversal budgets
    )

Semantics implemented here (deny-first AWS-style evaluation, condition
evaluation, fail-closed multi-route join, reason attribution) are documented
in ``permission_eval`` — that module is the authoritative description of the
authorization reasoning. No DB access anywhere in this package: pure
functions over passed-in data, networkx + stdlib only.
"""
from __future__ import annotations

from .graph_builder import EdgeKind, NodeKind, build
from .path_finder import evaluate_path, find_reachable_sensitive_resources
from .permission_eval import (
    MAX_GROUP_DEPTH,
    MAX_TRUST_HOPS,
    REASON_CONDITION_MISMATCH,
    REASON_EXPLICIT_DENY,
    REASON_GRANTED,
    REASON_NO_ALLOW_PATH,
    REASON_TRUST_MISMATCH,
    VIA_CONSENT,
    VIA_DIRECT,
    VIA_GROUP,
    VIA_NESTED,
    VIA_RESOURCE_POLICY,
    VIA_TRUST,
    condition_failures,
    conditions_hold,
    evaluate_decision,
    expand_subject_chain,
)

__all__ = [
    "EdgeKind",
    "NodeKind",
    "MAX_GROUP_DEPTH",
    "MAX_TRUST_HOPS",
    "REASON_CONDITION_MISMATCH",
    "REASON_EXPLICIT_DENY",
    "REASON_GRANTED",
    "REASON_NO_ALLOW_PATH",
    "REASON_TRUST_MISMATCH",
    "VIA_CONSENT",
    "VIA_DIRECT",
    "VIA_GROUP",
    "VIA_NESTED",
    "VIA_RESOURCE_POLICY",
    "VIA_TRUST",
    "build",
    "condition_failures",
    "conditions_hold",
    "evaluate_decision",
    "evaluate_path",
    "expand_subject_chain",
    "find_reachable_sensitive_resources",
]
__version__ = "1.0.0"
