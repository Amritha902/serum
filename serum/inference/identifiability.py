"""Identifiability theory for vulnerability-gated exploit inference.

This is SERUM's theoretical core and the piece that differentiates it from
cascade-mixture identifiability (Hoffmann et al., ICML 2020): because the
propagation subgraph is fixed by *observable* node attributes (the CVE each host
carries), exploit-identifiability reduces to a **checkable combinatorial
condition on vulnerability profiles**, not a spectral property of latent graphs.

Setup. Host graph G; each host v carries a vulnerability profile X(v) subset of
the CVE universe C. A worm exploits an unknown target c*. Propagation is gated:
a host can be infected only if it carries c*. So every propagation-infected host
lies in the vulnerable subgraph G[c*] induced by carriers(c*), and the defender,
observing the infected set I (seeds excluded), knows only that c* is consistent
with I.

Key facts (see docs/THEORY.md for statements + proofs):

  * Posterior support after observing infected set I equals the CVEs carried by
    EVERY host in I:                       supp(I) = intersection_{v in I} X(v).
  * As a c*-outbreak saturates its reachable vulnerable component R, the support
    shrinks to supp(R). Thus c* is *identifiable* iff supp(R) = {c*}.
  * c' is forever confusable with c* (never excludable by any c*-cascade over R)
    iff R subset of carriers(c'). Globally: c' confusable with c* whenever
    carriers(c*) subset carriers(c').  ==> the confusability relation is exactly
    the subset partial order on carrier sets.

This module computes these quantities exactly and is validated empirically
against the Bayesian belief in scripts/identifiability.py.
"""

from __future__ import annotations

import networkx as nx
import numpy as np


def carriers(g: nx.Graph, cve: int) -> set:
    """Hosts exploitable by ``cve`` -- the support of the vulnerable subgraph."""
    return {v for v, d in g.nodes(data=True) if cve in d["vuln"]}


def support_over(g: nx.Graph, nodes) -> set:
    """CVEs carried by *every* host in ``nodes`` (the exact posterior support of
    a noiseless observer who has seen exactly this infected set)."""
    nodes = list(nodes)
    if not nodes:
        return set(range(g.graph["n_cves"]))
    inter = set(g.nodes[nodes[0]]["vuln"])
    for v in nodes[1:]:
        inter &= g.nodes[v]["vuln"]
        if len(inter) == 1:
            break
    return inter


def reachable_component(g: nx.Graph, cve: int, seeds=None) -> set:
    """The vulnerable-subgraph component an outbreak of ``cve`` can saturate.

    Without seeds, returns the largest connected component of G[carriers(cve)]
    (the worst case for the fleet, best case for identifiability)."""
    sub = g.subgraph(carriers(g, cve))
    if sub.number_of_nodes() == 0:
        return set()
    comps = list(nx.connected_components(sub))
    if seeds is not None:
        seedset = set(seeds)
        hit = [c for c in comps if c & seedset]
        if hit:
            return set().union(*hit)
    return max(comps, key=len)


def is_identifiable(g: nx.Graph, cve: int, seeds=None) -> bool:
    """True iff a saturating outbreak of ``cve`` pins the posterior to {cve}."""
    R = reachable_component(g, cve, seeds)
    if not R:
        return False
    return support_over(g, R) == {cve}


def confusers(g: nx.Graph, cve: int, seeds=None) -> set:
    """CVEs that remain consistent even after a saturating ``cve`` outbreak
    (i.e. the residual ambiguity). Empty set <=> identifiable."""
    R = reachable_component(g, cve, seeds)
    if not R:
        return set(range(g.graph["n_cves"]))
    return support_over(g, R) - {cve}


def confusability_graph(g: nx.Graph) -> nx.DiGraph:
    """Directed graph on CVEs: edge c -> c' iff carriers(c) subset carriers(c')
    (c' can never be excluded when observing a full c-cascade). Self-loops
    omitted. A CVE with no out-edges is globally identifiable."""
    n = g.graph["n_cves"]
    car = {c: carriers(g, c) for c in range(n)}
    h = nx.DiGraph()
    h.add_nodes_from(range(n))
    for c in range(n):
        for cp in range(n):
            if c != cp and car[c] and car[c] <= car[cp]:
                h.add_edge(c, cp)
    return h


def identifiable_fraction(g: nx.Graph, seeds_by_cve=None) -> float:
    """Fraction of (carrier-bearing) CVEs that are identifiable from a saturating
    outbreak -- a single scalar summary of a network's exploit-observability."""
    n = g.graph["n_cves"]
    live = [c for c in range(n) if carriers(g, c)]
    if not live:
        return 0.0
    ok = sum(1 for c in live if is_identifiable(g, c,
             None if seeds_by_cve is None else seeds_by_cve.get(c)))
    return ok / len(live)


def spread_potential(g: nx.Graph, cve: int, seeds=None) -> int:
    """S(c): the number of hosts a worm exploiting ``cve`` can reach (the size of
    its reachable vulnerable component) -- the maximum outbreak size."""
    return len(reachable_component(g, cve, seeds))


def n_cves_at_least(g: nx.Graph, prevalence: float) -> int:
    """N(pi): how many CVEs have prevalence >= pi. Non-increasing in pi."""
    prev = _prevalence_vector(g)
    return int((prev >= prevalence).sum())


def _prevalence_vector(g: nx.Graph) -> np.ndarray:
    n = g.graph["n_cves"]
    counts = np.zeros(n)
    for _, d in g.nodes(data=True):
        for c in d["vuln"]:
            counts[c] += 1
    return counts / g.number_of_nodes()


def anonymity_bound(g: nx.Graph, cve: int, seeds=None) -> int:
    """The spread-anonymity duality bound: the number of confusers of ``cve`` is
    at most N(S(c)/n) - 1, where N is the prevalence complementary count. Every
    confuser c' satisfies R(c) subset carriers(c'), so prevalence(c') >= S(c)/n;
    hence confusers are drawn only from CVEs at least that prevalent."""
    s = spread_potential(g, cve, seeds)
    if s == 0:
        return g.graph["n_cves"] - 1
    return n_cves_at_least(g, s / g.number_of_nodes()) - 1


def duality_table(g: nx.Graph) -> list:
    """Per-CVE (spread, anonymity, bound) for empirically validating the duality
    theorem: anonymity <= bound must hold for every CVE, and the achievable
    (spread, anonymity) frontier is downward-sloping."""
    rows = []
    for c in range(g.graph["n_cves"]):
        if not carriers(g, c):
            continue
        s = spread_potential(g, c)
        a = len(confusers(g, c))
        rows.append({"cve": c, "spread": s, "spread_frac": s / g.number_of_nodes(),
                     "anonymity": a, "bound": anonymity_bound(g, c),
                     "satisfies_bound": a <= anonymity_bound(g, c)})
    return rows


def identifiability_report(g: nx.Graph) -> dict:
    """Per-CVE identifiability + residual confusers, plus the fleet summary."""
    n = g.graph["n_cves"]
    rows = []
    for c in range(n):
        car = carriers(g, c)
        if not car:
            continue
        conf = confusers(g, c)
        rows.append({"cve": c, "prevalence": round(len(car) / g.number_of_nodes(), 3),
                     "identifiable": len(conf) == 0, "n_confusers": len(conf),
                     "confusers": sorted(conf)})
    return {"n_cves_live": len(rows),
            "identifiable_fraction": round(identifiable_fraction(g), 3),
            "per_cve": rows}
