"""Attack-graph construction for SPECTER X (Track A, task sx-4).

Turns the authorization records of CONTRACTS §2 into a *directed attack
graph*: nodes are security principals (users, groups, apps, roles) and assets
(resources); edges are grants. Every edge points in the direction that access
FLOWS — principal → resource — so that path finding can answer the one
question this tool exists for: "which sensitive resources can this identity
reach, and through which grants?"

Input shapes accepted by :func:`build`
--------------------------------------
* an org.json-style dict (has a ``grants`` key, plus optional ``identities``,
  ``resources``, ``groups``/``apps``/``roles`` label maps and the org-level
  ``scope_resources`` mapping), or
* any iterable of grant records — plain dicts **or** SQLAlchemy ``Grant`` ORM
  rows. Detection is per item: mapping key access vs attribute access, so a
  mixed list works too.

Edge normalization (record orientation → graph orientation)
-----------------------------------------------------------
===========================  ==========================  =========================================
kind                         record says                 graph edge
===========================  ==========================  =========================================
GROUP_MEMBER                 member → group              member → group (nesting = group → parent)
DIRECTORY_ROLE               member → role               member → role
TRUST_ASSUME                 principal → assumable       principal → assumable
APP_CONSENT                  principal → app             principal → app
IDENTITY_POLICY_ALLOW/DENY   subject → resource          subject → resource
RESOURCE_POLICY              resource → principal        **flipped**: principal → resource
===========================  ==========================  =========================================

The RESOURCE_POLICY flip is deliberate: the record stores the grant "from the
resource's point of view" ("this resource trusts that principal"), but in an
attack graph the edge must point along the attacker's walk, otherwise
reachability from identity to resource is unnavigable. Consumers that need the
record orientation can read it from the edge's ``grants`` payload; the edge
``kind`` is unchanged, so the CONTRACTS §2 vocabulary is intact.

Deliberately NOT materialized: the org-level ``scope_resources`` mapping
(which OAuth scope unlocks which resource). It is org config, not a grant —
materializing it would add an edge kind that CONTRACTS §2 does not define.
It travels on ``graph.graph["scope_resources"]`` and is consumed at
evaluation time by the APP_CONSENT delegation logic in ``permission_eval``.

Parallel grants between the same node pair are merged onto one edge; the full
list rides in the edge attribute ``grants`` (the primary ``grant_id`` /
``kind`` stay directly on the edge for the CONTRACTS §2 wire shape).

Note on the ``verified`` flag (APP_CONSENT): it marks publisher verification —
a *risk* signal that feeds detector D4 — but it is **not** an authorization
gate. A consent to an unverified app still delegates the consented scopes
(that is what makes unverified consents dangerous in the first place), so
reachability treats verified and unverified consents identically.

Pure functions over passed-in data — networkx + stdlib only, no DB access.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

import networkx as nx

RES_PREFIX = "res-"
GROUP_PREFIX = "grp-"
APP_PREFIX = "app-"
ROLE_PREFIX = "role-"
USER_PREFIXES = ("usr-", "svc-")

#: Resource sensitivity value (CONTRACTS §2) that terminates attack paths.
SENSITIVE = "sensitive"


class NodeKind:
    """Vocabulary for ``node["kind"]`` (CONTRACTS §2 / API graph shape)."""

    USER = "user"
    GROUP = "group"
    APP = "app"
    ROLE = "role"
    RESOURCE = "resource"


class EdgeKind:
    """Vocabulary for ``edge["kind"]`` — exactly the CONTRACTS §2 grant kinds.

    No derived kinds: the graph must stay a faithful picture of the grant
    records so that every edge on screen is traceable to one ``grant_id``.
    """

    IDENTITY_POLICY_ALLOW = "IDENTITY_POLICY_ALLOW"
    IDENTITY_POLICY_DENY = "IDENTITY_POLICY_DENY"
    RESOURCE_POLICY = "RESOURCE_POLICY"
    TRUST_ASSUME = "TRUST_ASSUME"
    GROUP_MEMBER = "GROUP_MEMBER"
    APP_CONSENT = "APP_CONSENT"
    DIRECTORY_ROLE = "DIRECTORY_ROLE"


_GRANT_KINDS = frozenset(
    {
        EdgeKind.IDENTITY_POLICY_ALLOW,
        EdgeKind.IDENTITY_POLICY_DENY,
        EdgeKind.RESOURCE_POLICY,
        EdgeKind.TRUST_ASSUME,
        EdgeKind.GROUP_MEMBER,
        EdgeKind.APP_CONSENT,
        EdgeKind.DIRECTORY_ROLE,
    }
)


def _field(record: Any, key: str, default: Any = None) -> Any:
    """Read ``key`` from a dict **or** an ORM row (attribute) uniformly.

    This is the dict-vs-Grant-ORM duck detection the contract asks for.
    """
    if isinstance(record, Mapping):
        return record.get(key, default)
    return getattr(record, key, default)


def _node_kind(node_id: str) -> str:
    """Infer a node's kind from its id prefix (CONTRACTS §2 id scheme).

    Unknown prefixes default to ``user``: ids in this system are always
    prefixed, and defaulting to the least privileged principal kind is the
    safe choice for anything unexpected.
    """
    if node_id.startswith(RES_PREFIX):
        return NodeKind.RESOURCE
    if node_id.startswith(GROUP_PREFIX):
        return NodeKind.GROUP
    if node_id.startswith(APP_PREFIX):
        return NodeKind.APP
    if node_id.startswith(ROLE_PREFIX):
        return NodeKind.ROLE
    return NodeKind.USER


def _normalize_grant(record: Any) -> dict[str, Any]:
    """Validate one grant record (dict or ORM row) into a plain dict.

    Raises loudly on malformed input: silently dropping an authorization edge
    in a security tool would understate exposure — the exact failure mode this
    product must never have.
    """
    gid = _field(record, "grant_id")
    kind = _field(record, "kind")
    if not gid or not kind:
        raise ValueError(f"grant record missing grant_id/kind: {record!r}")
    if kind not in _GRANT_KINDS:
        raise ValueError(f"unknown grant kind {kind!r} on grant {gid}")
    scopes = _field(record, "scopes")
    conditions = _field(record, "conditions")
    from_id = _field(record, "from_id")
    to_id = _field(record, "to_id")
    if not from_id or not to_id:
        raise ValueError(f"grant {gid} missing from_id/to_id")
    return {
        "grant_id": gid,
        "kind": kind,
        "from_id": from_id,
        "to_id": to_id,
        "resource_id": _field(record, "resource_id"),
        "scopes": list(scopes) if scopes else [],
        "conditions": dict(conditions) if conditions else None,
        "verified": bool(_field(record, "verified", True)),
    }


def _policy_target(grant: dict[str, Any]) -> str:
    """Resolve which node a policy grant (ALLOW/DENY) points at.

    org.json stores the resource in ``to_id``; the ORM also allows the
    dedicated ``resource_id`` column. Prefer an explicit ``res-*`` value in
    either field.
    """
    for candidate in (grant["resource_id"], grant["to_id"]):
        if isinstance(candidate, str) and candidate.startswith(RES_PREFIX):
            return candidate
    return grant["to_id"]


def _resource_policy_endpoints(grant: dict[str, Any]) -> tuple[str, str]:
    """Return ``(principal, resource)`` for a RESOURCE_POLICY grant.

    The record is written resource → principal ("this resource trusts that
    principal"); we normalize to principal → resource so the edge points along
    the attacker's walk (see module docstring).
    """
    if grant["from_id"].startswith(RES_PREFIX):
        return grant["to_id"], grant["from_id"]
    if grant["to_id"].startswith(RES_PREFIX):
        # Already stored principal-first; accept that orientation too.
        return grant["from_id"], grant["to_id"]
    resource = grant["resource_id"] or grant["from_id"]
    return grant["to_id"], resource


def _ensure_node(G: nx.DiGraph, node_id: str, **attrs: Any) -> None:
    """Create a node if absent, filling only attributes not already set."""
    if node_id not in G:
        base: dict[str, Any] = {
            "kind": _node_kind(node_id),
            "label": node_id,
            # Roles are privileged by definition (CONTRACTS §2: DIRECTORY_ROLE
            # implies a high-privilege flag); everyone else needs evidence.
            "privileged": node_id.startswith(ROLE_PREFIX),
            "sensitive": False,
        }
        base.update(attrs)
        G.add_node(node_id, **base)
    else:  # enrich (e.g. identity record arriving after an edge referenced it)
        for key, value in attrs.items():
            G.nodes[node_id].setdefault(key, value)


def _merge_edge(G: nx.DiGraph, u: str, v: str, grant: dict[str, Any]) -> None:
    """Add (or merge) one grant as edge ``u → v``.

    DiGraph collapses parallel edges, so multiple grants between the same pair
    are accumulated in ``edge["grants"]``; the first grant's id/kind remain on
    the edge itself to satisfy the CONTRACTS §2 wire shape.
    """
    light = {
        "grant_id": grant["grant_id"],
        "kind": grant["kind"],
        "conditions": grant["conditions"],
        "scopes": list(grant["scopes"]),
    }
    if G.has_edge(u, v):
        data = G.edges[u, v]
        if all(existing["grant_id"] != light["grant_id"] for existing in data["grants"]):
            data["grants"].append(light)
        return
    G.add_edge(
        u,
        v,
        kind=light["kind"],
        grant_id=light["grant_id"],
        conditions=light["conditions"],
        scopes=list(light["scopes"]),
        grants=[light],
    )


def build(
    source: Mapping[str, Any] | Iterable[Any],
    *,
    identities: Iterable[Any] | None = None,
    resources: Iterable[Any] | None = None,
    scope_resources: Mapping[str, list[str]] | None = None,
) -> nx.DiGraph:
    """Build the attack graph from an org dict **or** a sequence of grants.

    Accepts either an org.json-style mapping (``grants`` key present) or any
    iterable of grant records — plain dicts and SQLAlchemy ``Grant`` ORM rows
    alike (detected per item via :func:`_field`). Optional ``identities`` /
    ``resources`` / ``scope_resources`` enrich nodes when the input is a bare
    grant sequence; an org dict supplies them itself.

    Returns an ``nx.DiGraph`` whose nodes carry ``kind`` / ``label`` /
    ``privileged`` / ``sensitive`` and whose edges carry ``grant_id`` / ``kind``
    (plus the merged ``grants`` payload) — the CONTRACTS §2 graph contract.
    """
    label_by_id: dict[str, str] = {}
    if isinstance(source, Mapping):
        if "grants" not in source:
            if "grant_id" in source:
                grant_records: list[Any] = [source]
            else:
                raise ValueError(
                    "build() expects an org-style dict with a 'grants' key, "
                    "a single grant dict, or an iterable of grants"
                )
        else:
            grant_records = source["grants"]
            identities = identities if identities is not None else source.get("identities")
            resources = resources if resources is not None else source.get("resources")
            if scope_resources is None:
                scope_resources = source.get("scope_resources")
            # Label maps are {slug: id}; invert so we can label by node id.
            for map_key in ("groups", "apps", "roles"):
                for slug, node_id in (source.get(map_key) or {}).items():
                    label_by_id[node_id] = slug
    else:
        grant_records = source

    G = nx.DiGraph()
    # The scope map is needed at evaluation time (APP_CONSENT delegation), so
    # it travels with the graph; permission_eval never needs the raw org dict.
    G.graph["scope_resources"] = dict(scope_resources or {})

    for ident in identities or []:
        ident_id = _field(ident, "identity_id") or _field(ident, "id")
        if not ident_id:
            continue
        _ensure_node(
            G,
            ident_id,
            kind=NodeKind.USER,  # service accounts are principals too → node kind "user"
            label=_field(ident, "display_name", ident_id),
            privileged=bool(_field(ident, "privileged", False)),
            identity_kind=_field(ident, "kind", "user"),
        )

    for res in resources or []:
        res_id = _field(res, "resource_id") or _field(res, "id")
        if not res_id:
            continue
        _ensure_node(
            G,
            res_id,
            kind=NodeKind.RESOURCE,
            label=_field(res, "label", res_id),
            sensitive=_field(res, "sensitivity") == SENSITIVE,
        )

    for record in grant_records:
        grant = _normalize_grant(record)
        kind = grant["kind"]
        u, v = grant["from_id"], grant["to_id"]

        if kind in (EdgeKind.IDENTITY_POLICY_ALLOW, EdgeKind.IDENTITY_POLICY_DENY):
            _ensure_node(G, u)
            target = _policy_target(grant)
            _ensure_node(G, target)
            _merge_edge(G, u, target, grant)
        elif kind == EdgeKind.RESOURCE_POLICY:
            principal, resource = _resource_policy_endpoints(grant)
            _ensure_node(G, principal)
            _ensure_node(G, resource)
            # Flipped on purpose: access flows principal → resource (docstring).
            _merge_edge(G, principal, resource, grant)
        elif kind == EdgeKind.APP_CONSENT:
            _ensure_node(G, u)
            _ensure_node(G, v, label=label_by_id.get(v, v))
            _merge_edge(G, u, v, grant)
            # What the app may touch is resolved at evaluation time from
            # graph.graph["scope_resources"] — org config, not a grant, so it
            # must not appear as a graph edge (see module docstring).
        else:  # GROUP_MEMBER | DIRECTORY_ROLE | TRUST_ASSUME
            _ensure_node(G, u)
            _ensure_node(G, v, label=label_by_id.get(v, v))
            _merge_edge(G, u, v, grant)

    return G
