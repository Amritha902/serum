"""Diversity-for-observability: engineer the fleet so outbreaks self-reveal.

Motivation. In a monoculture fleet, many CVEs share carrier sets — carriers(x)
sits inside carriers(y), so a full x-outbreak's evidence is also consistent
with y and x is not identifiable. Confusability is not fate: a defender with a
small budget of *canary hosts* (deliberately-provisioned machines with a chosen
software profile) can break the subset-order dominances and force outbreaks to
reveal their payload.

Why canaries are monotone. Adding a host v to the fleet only *grows* each
carriers(c). For every existing witness (v', x, y) — a v' with x ∈ vuln(v') and
y ∉ vuln(v') that already broke ``carriers(x) ⊆ carriers(y)`` — v' remains a
witness after v is added. So adding a canary can only *break* subset-order
edges, never create new ones. Consequence: ``identifiable_fraction`` is
monotone non-decreasing in the canary set. This is the property that lets us
plan greedily without regret.

Singleton canaries: simple, monotone, and hit the natural K_live-I0 upper
bound. A canary with profile ``{c}`` witnesses ``x ∉ carriers(c)`` for every
``x ≠ c``, so it breaks every outgoing edge ``c → *`` in the subset-order
graph — pinning CVE c to globally identifiable in one shot. Therefore ``B``
singleton canaries give ``min(B, K_live - I0_global)`` additional globally-
identifiable CVEs, and the greedy planner terminates in exactly
``K_live - I0_global`` steps.

They are NOT necessarily *minimum-canary* optimal — a well-chosen multi-CVE
canary ``{c1, c2}`` can pin both c1 and c2 in one shot when their dominators
are disjoint (the canary witnesses c1's dominators for c1 and c2's dominators
for c2 simultaneously). Solving for the minimum canary count is a set-cover
instance (cover all confused pairs); singleton greedy is a simple upper bound
that we compare against a random-singleton baseline. Chasing minimum-count
optimality with multi-CVE canaries is a natural follow-up.

Operational identifiability (the outbreak-saturation notion, which is what a
real defender consumes) requires the canary to lie in the reachable vulnerable
component of the CVE it pins. We attach a ``{c}``-canary as a leaf to any
existing host in ``reachable_component(g, c)``; the augmented reachable
component now contains the canary, so ``supp(R) ⊆ vuln(canary) = {c}``. If no
such host exists (c has no carriers at all in the fleet), a canary alone cannot
help — you'd need to also attach a c-carrier for the canary to reach.

Random-profile baseline. Uniformly-random canaries (fixed profile size, drawn
from the CVE universe) also help — every {c}-inclusion breaks c's outgoing
edges — but a random profile of size s only pins a CVE ``c`` when ``c`` is the
sole "unique" contribution, so budget scales poorly compared to targeted
singletons. The experiment shows the gap directly.
"""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx
import numpy as np

from serum.inference.identifiability import (
    carriers,
    confusability_graph,
    confusers,
    is_identifiable,
    reachable_component,
    support_over,
)


@dataclass
class CanaryPlan:
    """A planned sequence of canary insertions.

    Each entry is ``(profile, attach_to)``: ``profile`` is the frozenset of
    CVEs the canary is vulnerable to; ``attach_to`` is either ``None`` (canary
    is a leaf disconnected from the rest of the graph, sufficient for *global*
    identifiability) or a node id in the existing graph (canary is a leaf on
    that host, sufficient for *operational* identifiability).
    """

    entries: list

    def __len__(self) -> int:
        return len(self.entries)


def add_canary(g: nx.Graph, profile, attach_to=None,
               node_id=None) -> object:
    """Add a canary host to ``g`` in place with the chosen vulnerability profile.

    Returns the new node's id. If ``attach_to`` is given, the canary is added
    as a leaf on that existing host, so it participates in outbreaks of any
    CVE both of them carry (essential for operational identifiability).
    """
    if node_id is None:
        node_id = f"canary_{sum(1 for v in g.nodes() if str(v).startswith('canary_'))}"
    prof = frozenset(int(c) for c in profile)
    if any(c < 0 or c >= g.graph["n_cves"] for c in prof):
        raise ValueError(f"canary profile {sorted(prof)} out of CVE range")
    g.add_node(node_id, vuln=prof, is_canary=True)
    if attach_to is not None:
        if attach_to not in g:
            raise ValueError(f"attach_to={attach_to!r} not in graph")
        g.add_edge(node_id, attach_to)
    return node_id


def apply_plan(g: nx.Graph, plan: CanaryPlan) -> nx.Graph:
    """Return a *copy* of ``g`` with all canaries in ``plan`` inserted."""
    h = g.copy()
    for i, (profile, attach_to) in enumerate(plan.entries):
        add_canary(h, profile, attach_to=attach_to, node_id=f"canary_{i}")
    return h


def _unidentifiable_cves(g: nx.Graph, mode: str) -> list:
    """CVEs that are live but not yet identifiable under ``mode``."""
    K = g.graph["n_cves"]
    live = [c for c in range(K) if carriers(g, c)]
    if mode == "global":
        cg = confusability_graph(g)
        return [c for c in live if cg.out_degree(c) > 0]
    if mode == "operational":
        return [c for c in live if not is_identifiable(g, c)]
    raise ValueError(f"unknown mode {mode!r}")


def _identifiable_count(g: nx.Graph, mode: str) -> int:
    K = g.graph["n_cves"]
    live = [c for c in range(K) if carriers(g, c)]
    if mode == "global":
        cg = confusability_graph(g)
        return sum(1 for c in live if cg.out_degree(c) == 0)
    if mode == "operational":
        return sum(1 for c in live if is_identifiable(g, c))
    raise ValueError(f"unknown mode {mode!r}")


def _live_count(g: nx.Graph) -> int:
    return sum(1 for c in range(g.graph["n_cves"]) if carriers(g, c))


def _rank_key_global(g: nx.Graph, c: int) -> tuple:
    """Prefer CVEs that are dominated by MANY others (breaking c pins one CVE
    each, so any tie-break by dominator count is a rough approximation of
    marginal value; we mostly want deterministic ordering)."""
    cg = confusability_graph(g)
    return (-cg.out_degree(c), c)


def _rank_key_operational(g: nx.Graph, c: int) -> tuple:
    """Prefer CVEs with the largest reachable component (biggest sample-
    complexity savings by pinning) and, secondarily, most confusers."""
    R = reachable_component(g, c)
    return (-len(R), -len(confusers(g, c)), c)


def greedy_canary_plan(g: nx.Graph, budget: int, mode: str = "global",
                       rng: np.random.Generator | None = None) -> CanaryPlan:
    """Greedy: at each step pick a currently-unidentifiable CVE and add a
    singleton ``{c}`` canary that pins it (see module docstring for optimality).

    In ``operational`` mode the canary is attached to a host in
    ``reachable_component(g, c)`` so the augmented outbreak actually visits it.
    In ``global`` mode the canary needs no attachment (global identifiability
    is a property of carrier sets alone).

    Ties are broken deterministically by out-degree in the subset-order graph
    (``global``) or reachable-component size (``operational``), then CVE id.
    """
    rng = rng or np.random.default_rng(0)
    h = g.copy()
    entries: list = []
    for _ in range(int(budget)):
        cands = _unidentifiable_cves(h, mode)
        if not cands:
            break
        if mode == "global":
            cands.sort(key=lambda c: _rank_key_global(h, c))
        else:
            cands.sort(key=lambda c: _rank_key_operational(h, c))
        c = cands[0]
        attach_to = None
        if mode == "operational":
            R = reachable_component(h, c)
            if R:
                # deterministic pick: the min-id host in R (a leaf attachment
                # to R suffices to fold the canary into the saturating outbreak)
                attach_to = sorted(R, key=lambda v: str(v))[0]
        entries.append((frozenset({c}), attach_to))
        add_canary(h, {c}, attach_to=attach_to, node_id=f"canary_plan_{len(entries) - 1}")
    return CanaryPlan(entries)


def random_canary_plan(g: nx.Graph, budget: int, profile_size: int = 1,
                       mode: str = "global",
                       rng: np.random.Generator | None = None) -> CanaryPlan:
    """Baseline: canary profiles are drawn uniformly at random from the CVE
    universe with fixed ``profile_size`` (default 1, matching greedy so the
    only difference is *which* CVEs are pinned)."""
    rng = rng or np.random.default_rng(0)
    K = g.graph["n_cves"]
    entries: list = []
    for _ in range(int(budget)):
        prof = frozenset(int(x) for x in rng.choice(K, size=profile_size, replace=False))
        attach_to = None
        if mode == "operational":
            # attach to some host that already carries at least one profile CVE
            # (else the canary is invisible to outbreaks of anything it covers)
            candidates = set().union(*(carriers(g, c) for c in prof))
            if candidates:
                attach_to = sorted(candidates, key=lambda v: str(v))[
                    int(rng.integers(len(candidates)))
                ]
        entries.append((prof, attach_to))
    return CanaryPlan(entries)


def identifiability_curve(g: nx.Graph, budgets, mode: str = "global",
                          strategy: str = "greedy",
                          rng: np.random.Generator | None = None) -> list:
    """Sweep the canary budget and report ``identifiable_fraction`` at each B.

    ``strategy`` selects the planner: ``"greedy"`` uses ``greedy_canary_plan``,
    ``"random"`` uses ``random_canary_plan`` (singleton profiles). Live-count
    grows with B (each canary can introduce a previously-dead CVE), so we
    report both the count of identifiable live CVEs and the fraction of the
    *augmented* live set.
    """
    rng = rng or np.random.default_rng(0)
    max_b = max(budgets)
    if strategy == "greedy":
        plan = greedy_canary_plan(g, max_b, mode=mode, rng=rng)
    elif strategy == "random":
        plan = random_canary_plan(g, max_b, profile_size=1, mode=mode, rng=rng)
    else:
        raise ValueError(f"unknown strategy {strategy!r}")

    out = []
    for B in sorted(set(int(x) for x in budgets)):
        sub_plan = CanaryPlan(plan.entries[:B])
        h = apply_plan(g, sub_plan)
        live = _live_count(h)
        ident = _identifiable_count(h, mode)
        out.append({
            "B": B, "mode": mode, "strategy": strategy,
            "live": live,
            "identifiable": ident,
            "identifiable_fraction": ident / live if live else 0.0,
        })
    return out


def budget_to_full_identifiability(g: nx.Graph, mode: str = "global",
                                   max_budget: int | None = None) -> int:
    """Minimum canary budget the greedy plan needs to reach 100% identifiability.

    Returns ``max_budget`` if it doesn't converge within that many steps
    (defensive; with singleton canaries greedy always converges in at most
    ``K_live - I0`` steps)."""
    K = g.graph["n_cves"]
    if max_budget is None:
        max_budget = 2 * K
    plan = greedy_canary_plan(g, max_budget, mode=mode)
    h = apply_plan(g, plan)
    live = _live_count(h)
    ident = _identifiable_count(h, mode)
    if ident == live:
        return len(plan)
    return max_budget
