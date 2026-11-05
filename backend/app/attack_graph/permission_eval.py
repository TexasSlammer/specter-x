"""Reachability semantics for the SPECTER X attack graph (Track A, task sx-4).

This module is the authorization brain: it decides, for one identity, one
resource and one evaluation context, whether an attacker operating in that
context can reach the resource — and it must be able to *prove* the answer via
grant ids.

Semantics (CONTRACTS §2, implemented exactly)
---------------------------------------------
1. **Candidate routes.** All of: direct identity grants, transitive group
   membership (nesting budget: 5 group hops), TRUST_ASSUME chains (budget:
   5 trust hops), APP_CONSENT delegation (a consented app acts toward the
   resources the org's ``scope_resources`` map binds to the consented scopes —
   org config consumed at evaluation time, not a grant), and RESOURCE_POLICY
   (cross-boundary access that needs **no** identity allow).
2. **Deny wins — evaluation is deny-first.** An explicit IDENTITY_POLICY_DENY
   on *any* subject in the chain overrides every allow (AWS semantics). This
   is why deny is checked *before* any allow analysis: an explicit "no" is a
   negative authorization no allow can cancel, and it must be reported even
   when no allow path exists at all (ground truth: usr-connor.wells →
   res-hr-portal is ``explicit_deny``, not ``no_allow_path``). The deny
   subject set is the identity, every inherited group (≤5 nesting hops) and
   every principal reachable through TRUST_ASSUME — deliberately
   conservative: a deny pinned on an assumable principal must not become
   bypassable merely because the assumee also holds an unconditional allow.
3. **Conditions.** ``ip_in`` (plain IPs and CIDR nets), ``time_window``
   ``"HH:MM-HH:MM"`` (bounds inclusive, overnight wrap supported) and
   ``asn_type_in`` must hold against the ctx ``{ip, asn_type, time}``.
   Fail-closed everywhere: a missing ctx value, an unparseable time or an
   *unrecognized* condition key means the condition does not hold — an
   evaluator that guesses would overstate access, which is the one failure
   mode a security tool must never have. A *conditional* deny only applies
   when its own conditions hold (AWS conditional-deny semantics); an
   unconditional deny always applies.
4. **Fail-closed multi-route join (dataset-mandated).** ground_truth.json
   requires ``usr-flores → res-backup-vault`` to be **denied** under
   ``asn_type=datacenter`` even though ``grp-it-admins`` holds an
   *unconditional* allow on the vault — because the trust route to the same
   resource (grp-it-admins → breakglass role) is ASN-gated. We therefore
   evaluate a resource as reachable only when **every** candidate route for
   this subject is valid: one condition-gated route tightens all routes.
   Rationale: the org has expressed, via a gated route, that this resource is
   context-sensitive; the evaluator refuses to certify reachability it cannot
   guarantee on every route. (Tension with pure union semantics is flagged to
   the contract owners in the Track A report.)
5. **Reason attribution.** When the subject is denied:
   - ``explicit_deny`` — an applicable deny exists (checked first);
   - ``condition_mismatch`` — routes exist but at least one fails on a
     non-trust condition, **or** some route is valid while another fails
     (this is exactly the flores@datacenter shape, which ground truth pins to
     ``condition_mismatch``);
   - ``trust_mismatch`` — *every* route failed and all failures sit on
     TRUST_ASSUME conditions (a trust-only route whose ASN gate rejected the
     session);
   - ``no_allow_path`` — no candidate route at all.

``via`` attribution (which route to report when reachable) is ordered by how
much an attacker must control to use it — the less control needed for the
same access, the more attack-relevant the route:

    trust_assume_chain > group_allow > nested_group > consent_delegation
    > resource_policy > direct

Ground truth fixes two points of this order: flores→vault must report
``trust_assume_chain`` over the co-existing group allow, and
reyes→billing-exports must report ``group_allow`` over the co-existing consent
delegation.

Note on ``verified`` (APP_CONSENT): publisher verification is a risk signal
(detector D4), not an authorization gate — an unverified consent still
delegates its scopes, which is precisely why it is dangerous.

Pure functions over the graph + ctx. No DB access. networkx + stdlib only.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from .graph_builder import EdgeKind

#: Group-nesting budget (CONTRACTS §2: groups may nest, max depth 5).
MAX_GROUP_DEPTH = 5
#: TRUST_ASSUME chain budget (task contract: max 5 hops).
MAX_TRUST_HOPS = 5

REASON_EXPLICIT_DENY = "explicit_deny"
REASON_CONDITION_MISMATCH = "condition_mismatch"
REASON_NO_ALLOW_PATH = "no_allow_path"
REASON_TRUST_MISMATCH = "trust_mismatch"
#: Reason reported when the request is granted.
REASON_GRANTED = "granted"

VIA_TRUST = "trust_assume_chain"
VIA_GROUP = "group_allow"
VIA_NESTED = "nested_group"
VIA_CONSENT = "consent_delegation"
VIA_RESOURCE_POLICY = "resource_policy"
VIA_DIRECT = "direct"

#: Lower number = more attack-relevant route = preferred ``via`` attribution.
_VIA_PRECEDENCE: dict[str, int] = {
    VIA_TRUST: 0,
    VIA_GROUP: 1,
    VIA_NESTED: 2,
    VIA_CONSENT: 3,
    VIA_RESOURCE_POLICY: 4,
    VIA_DIRECT: 5,
}


def _minutes(hhmm: str) -> int | None:
    """Parse ``"HH:MM"`` into minutes-since-midnight; None if malformed."""
    try:
        hours, minutes = hhmm.split(":")
        return int(hours) * 60 + int(minutes)
    except (ValueError, AttributeError):
        return None


def time_in_window(time_str: str | None, window: str) -> bool:
    """Is ``time_str`` (``"HH:MM"``) inside ``window`` (``"HH:MM-HH:MM"``)?

    Bounds are **inclusive** on both ends (a 09:00-17:00 window admits 09:00
    and 17:00 — the org's own all-day grant ``00:00-23:59`` only makes sense
    with inclusive bounds). Windows that wrap midnight (start > end, e.g.
    ``22:00-02:00``) match either side of midnight. Unparseable input fails
    closed (False).
    """
    if not time_str:
        return False
    now = _minutes(time_str)
    if now is None or "-" not in window:
        return False
    start_s, _, end_s = window.partition("-")
    start, end = _minutes(start_s.strip()), _minutes(end_s.strip())
    if start is None or end is None:
        return False
    if start <= end:
        return start <= now <= end
    return now >= start or now <= end  # overnight wrap


def ip_in(ip: str | None, allowed: list[str]) -> bool:
    """Is ``ip`` covered by ``allowed`` (plain IPs and/or CIDR nets)?

    CIDR support mirrors cloud policy engines; a non-parseable entry
    degrades to string equality instead of raising, because policy text is
    operator input and one bad entry must not break the whole check.
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip in allowed
    for entry in allowed:
        if "/" in str(entry):
            try:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
        elif str(addr) == str(entry):
            return True
    return False


def condition_failures(conditions: Mapping[str, Any] | None, ctx: Mapping[str, Any]) -> list[str]:
    """Keys of ``conditions`` that do NOT hold under ``ctx`` (empty = all hold).

    Fail-closed by design:
    * a known key (``ip_in`` / ``time_window`` / ``asn_type_in``) whose ctx
      value is missing or malformed is reported as failed — guessing would
      overstate access;
    * an explicit ``None`` value means "no constraint" and never fails (the
      grant records use null to say "unconditional");
    * an *unrecognized* non-null key is reported as failed: the org expressed
      a constraint this evaluator does not understand, so certifying access
      would be fabrication. (Forward compatibility is earned by shipping
      support, not by ignoring policy.)
    """
    failed: list[str] = []
    if not conditions:
        return failed

    enforced: set[str] = set()
    if conditions.get("ip_in") is not None:
        enforced.add("ip_in")
        if not ip_in(ctx.get("ip"), list(conditions["ip_in"])):
            failed.append("ip_in")
    if conditions.get("time_window") is not None:
        enforced.add("time_window")
        if not time_in_window(ctx.get("time"), conditions["time_window"]):
            failed.append("time_window")
    if conditions.get("asn_type_in") is not None:
        enforced.add("asn_type_in")
        if ctx.get("asn_type") not in list(conditions["asn_type_in"]):
            failed.append("asn_type_in")

    for key in conditions:
        if key not in enforced and conditions[key] is not None:
            failed.append(key)
    return failed


def conditions_hold(conditions: Mapping[str, Any] | None, ctx: Mapping[str, Any]) -> bool:
    """True iff every condition in the grant holds under the eval ctx.

    Conditions are conjunctive and fail closed — see :func:`condition_failures`
    for the per-key policy.
    """
    return not condition_failures(conditions, ctx)


@dataclass(frozen=True)
class _ChainHop:
    """One node in the expanded subject chain, with budgets and provenance.

    ``path_grants`` is the ordered grant-id evidence of how this node was
    reached; ``condition_grants`` collects ``(grant_id, conditions, is_trust)``
    for every *traversed* edge grant carrying conditions (trust-edge conditions
    gate the session they create, which is why they ride along).
    """

    node: str
    group_depth: int
    trust_hops: int
    used_trust: bool
    path_grants: tuple[str, ...]
    condition_grants: tuple[tuple[str, Mapping[str, Any] | None, bool], ...] = ()


def _edge_grants(data: Mapping[str, Any]) -> list[dict[str, Any]]:
    """All grant payloads merged onto an edge (builder guarantees the list)."""
    grants = data.get("grants")
    return list(grants) if grants else []


def _out_edges_sorted(graph: nx.DiGraph, node: str) -> list[tuple[str, str, dict]]:
    """Deterministic (u, v, data) out-edge list — stable reports and tests."""
    return sorted(
        ((u, v, dict(data)) for u, v, data in graph.out_edges(node, data=True)),
        key=lambda item: (item[1], item[2].get("kind", ""), item[2].get("grant_id", "")),
    )


def expand_subject_chain(graph: nx.DiGraph, identity_id: str) -> dict[str, _ChainHop]:
    """Expand the identity's *subject chain*: everyone the session can be.

    BFS from the identity over GROUP_MEMBER edges (each consumes one of 5
    group-depth slots — nesting deeper than that is not followed, per
    CONTRACTS §2) and TRUST_ASSUME edges (each consumes one of 5 trust-hop
    slots — bounded so assume-role cycles in a hostile directory cannot spin
    forever). The identity itself is always in the chain.

    Why bounded expansion matters: directory graphs are attacker-writable in
    the scenarios this tool investigates (role_grant_abuse), so traversal
    budgets are a termination guarantee first and a fidelity statement second.

    Returns ``{node: _ChainHop}``; first (cheapest) arrival wins.
    """
    start = _ChainHop(
        node=identity_id,
        group_depth=0,
        trust_hops=0,
        used_trust=False,
        path_grants=(),
    )
    chain = {identity_id: start}
    frontier = [start]
    while frontier:
        hop = frontier.pop(0)
        if hop.node not in graph:
            continue
        for _, dst, data in _out_edges_sorted(graph, hop.node):  # deterministic order
            kind = data.get("kind")
            if kind == EdgeKind.GROUP_MEMBER:
                if hop.group_depth >= MAX_GROUP_DEPTH:
                    continue  # nesting deeper than 5 is not followed
                new_depth, new_trust = hop.group_depth + 1, hop.trust_hops
            elif kind == EdgeKind.TRUST_ASSUME:
                if hop.trust_hops >= MAX_TRUST_HOPS:
                    continue  # trust chains cap at 5 hops
                new_depth, new_trust = hop.group_depth, hop.trust_hops + 1
            else:
                continue  # policy/consent edges are terminal, not chain links
            if dst in chain:
                continue
            traversed = tuple(
                (g["grant_id"], g.get("conditions"), g["kind"] == EdgeKind.TRUST_ASSUME)
                for g in _edge_grants(data)
                if g.get("conditions")
            )
            child = _ChainHop(
                node=dst,
                group_depth=new_depth,
                trust_hops=new_trust,
                used_trust=hop.used_trust or kind == EdgeKind.TRUST_ASSUME,
                path_grants=hop.path_grants + tuple(g["grant_id"] for g in _edge_grants(data)),
                condition_grants=hop.condition_grants + traversed,
            )
            chain[dst] = child
            frontier.append(child)
    return chain


@dataclass
class _Route:
    """One candidate allow route to the resource, with its verdict.

    ``valid`` means every condition-bearing grant on the route held under the
    ctx. ``failed_*`` flags record *where* it failed so reason attribution can
    distinguish trust-gate rejections from ordinary condition mismatches.
    """

    via: str
    path_grants: tuple[str, ...]
    valid: bool
    failed_trust: bool = False
    failed_other: bool = False
    failed_grant_ids: tuple[str, ...] = ()
    checks: tuple[tuple[str, Mapping[str, Any] | None, bool], ...] = field(default=())

    @classmethod
    def build(
        cls,
        via: str,
        path_grants: tuple[str, ...],
        checks: tuple[tuple[str, Mapping[str, Any] | None, bool], ...],
        ctx: Mapping[str, Any],
    ) -> _Route:
        """Evaluate all condition-bearing grants of the route against ctx."""
        failed_ids: list[str] = []
        failed_trust = failed_other = False
        for grant_id, cond, is_trust in checks:
            if not conditions_hold(cond, ctx):
                failed_ids.append(grant_id)
                # Trust-edge failures are a distinct reason (the *session*
                # created by assume-role was rejected); any other failure is
                # an ordinary condition mismatch on the resource grant itself.
                if is_trust:
                    failed_trust = True
                else:
                    failed_other = True
        return cls(
            via=via,
            path_grants=path_grants,
            valid=not failed_ids,
            failed_trust=failed_trust,
            failed_other=failed_other,
            failed_grant_ids=tuple(failed_ids),
            checks=checks,
        )


def _via_for_allow(hop: _ChainHop, node: str, identity_id: str) -> str:
    """Attribute an allow-grant route to the way its subject was reached."""
    if hop.used_trust:
        return VIA_TRUST
    if node == identity_id:
        return VIA_DIRECT
    if hop.group_depth <= 1:
        return VIA_GROUP
    return VIA_NESTED


def _candidate_routes(
    graph: nx.DiGraph,
    chain: dict[str, _ChainHop],
    resource_id: str,
    identity_id: str,
    ctx: Mapping[str, Any],
) -> list[_Route]:
    """Enumerate every candidate allow route to ``resource_id``.

    Three families: terminal policy grants (IDENTITY_POLICY_ALLOW from any
    chain subject, RESOURCE_POLICY from any chain principal) and consent
    delegation (chain subject → APP_CONSENT → app, which acts toward the
    resource because the org's ``scope_resources`` map binds one of the
    consented scopes to it). Each route carries the conditions of *all* its
    grants; trust-edge conditions collected along the chain gate the whole
    route.
    """
    scope_map: dict[str, list[str]] = graph.graph.get("scope_resources") or {}
    routes: list[_Route] = []
    for node, hop in chain.items():
        if node not in graph:
            continue
        for _, dst, data in _out_edges_sorted(graph, node):
            grants = _edge_grants(data)
            if dst == resource_id:
                for grant in grants:
                    checks = hop.condition_grants + ((grant["grant_id"], grant.get("conditions"), False),)
                    path = hop.path_grants + (grant["grant_id"],)
                    if grant["kind"] == EdgeKind.IDENTITY_POLICY_ALLOW:
                        routes.append(
                            _Route.build(_via_for_allow(hop, node, identity_id), path, checks, ctx)
                        )
                    elif grant["kind"] == EdgeKind.RESOURCE_POLICY:
                        via = VIA_TRUST if hop.used_trust else VIA_RESOURCE_POLICY
                        routes.append(_Route.build(via, path, checks, ctx))
            elif data.get("kind") == EdgeKind.APP_CONSENT:
                # The chain subject consented to this app; the app may act on
                # resources the org's scope map binds to the consented scopes.
                # No scope → no delegation: a consent is not a blank cheque.
                for grant in grants:
                    if grant["kind"] != EdgeKind.APP_CONSENT:
                        continue
                    for scope in grant.get("scopes") or []:
                        if resource_id not in scope_map.get(scope, []):
                            continue
                        checks = hop.condition_grants + (
                            (grant["grant_id"], grant.get("conditions"), False),
                        )
                        path = hop.path_grants + (grant["grant_id"],)
                        routes.append(_Route.build(VIA_CONSENT, path, checks, ctx))
    return routes


def _applicable_denies(
    graph: nx.DiGraph, chain: dict[str, _ChainHop], resource_id: str, ctx: Mapping[str, Any]
) -> list[str]:
    """Grant ids of denies that apply: subject in chain, target resource.

    A *conditional* deny only applies when its own conditions hold — AWS
    semantics again: an explicit deny is absolute, a conditional deny is
    scoped to the context it describes.
    """
    deny_ids: list[str] = []
    for node in chain:
        if node not in graph:
            continue
        for _, dst, data in _out_edges_sorted(graph, node):
            if dst != resource_id:
                continue
            for grant in _edge_grants(data):
                if grant["kind"] == EdgeKind.IDENTITY_POLICY_DENY and conditions_hold(
                    grant.get("conditions"), ctx
                ):
                    deny_ids.append(grant["grant_id"])
    return deny_ids


def _dedupe(ids: list[str] | tuple[str, ...]) -> list[str]:
    """Order-preserving dedup for evidence lists."""
    seen: set[str] = set()
    out: list[str] = []
    for gid in ids:
        if gid not in seen:
            seen.add(gid)
            out.append(gid)
    return out


def evaluate_decision(
    graph: nx.DiGraph,
    identity_id: str,
    resource_id: str,
    ctx: Mapping[str, Any],
) -> dict[str, Any]:
    """Core verdict: can ``identity_id`` reach ``resource_id`` under ``ctx``?

    Order of analysis mirrors the contract: deny-first, then routes, then the
    fail-closed join (see module docstring for why the join is fail-closed).

    Returns ``{"reachable", "reason", "via", "evidence", "paths"}`` where
    ``evidence`` cites grant ids (deny grants, failing grants, or the winning
    route's chain) and ``paths`` lists valid evidence chains.
    """
    chain = expand_subject_chain(graph, identity_id)

    # 1. Deny wins, always and first: an explicit deny is a negative
    #    authorization that no allow — direct, inherited or assumed — can
    #    resurrect. Reported even when no allow path exists at all.
    deny_ids = _applicable_denies(graph, chain, resource_id, ctx)
    if deny_ids:
        return {
            "reachable": False,
            "reason": REASON_EXPLICIT_DENY,
            "via": None,
            "evidence": _dedupe(deny_ids),
            "paths": [],
        }

    # 2. Candidate routes.
    routes = _candidate_routes(graph, chain, resource_id, identity_id, ctx)
    if not routes:
        return {
            "reachable": False,
            "reason": REASON_NO_ALLOW_PATH,
            "via": None,
            "evidence": [],
            "paths": [],
        }

    valid = [route for route in routes if route.valid]
    if len(valid) == len(routes):
        # 3a. Every route valid → reachable. Report the most attack-relevant
        #     route as `via` and keep all valid chains as evidence.
        ranked = sorted(routes, key=lambda r: (_VIA_PRECEDENCE[r.via], r.path_grants))
        best = ranked[0]
        return {
            "reachable": True,
            "reason": REASON_GRANTED,
            "via": best.via,
            "evidence": list(best.path_grants),
            "paths": [list(route.path_grants) for route in ranked],
        }

    # 3b. Fail-closed: at least one route failed its conditions, so the
    #     resource is context-locked for this subject (module docstring §4).
    failed = [route for route in routes if not route.valid]
    failed_other = any(route.failed_other for route in failed)
    failed_trust = any(route.failed_trust for route in failed)
    if failed_other or valid:
        # Ground truth pins the mixed case (a clean route exists, a trust
        # route failed) to the generic condition mismatch; trust_mismatch is
        # reserved for routes that failed *only* on trust gates.
        reason = REASON_CONDITION_MISMATCH
    elif failed_trust:
        reason = REASON_TRUST_MISMATCH
    else:
        reason = REASON_CONDITION_MISMATCH
    bad_ids = [gid for route in failed for gid in route.failed_grant_ids]
    return {
        "reachable": False,
        "reason": reason,
        "via": None,
        "evidence": _dedupe(bad_ids),
        "paths": [],
    }
