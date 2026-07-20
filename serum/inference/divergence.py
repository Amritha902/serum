"""Zone-hub divergence: a *measured* property that indexes content-aware benefit.

Motivation. SERUM's content-aware advantage over structure-only defenders (like
DegreeDefense) is often described as "the payload's vulnerable subgraph differs
from the physical topology, so degree-ranked hubs are the wrong targets." The
homophily knob in the real-data profile generator lets us dial this in
synthetically, but it isn't a property a real fleet has — you can't measure the
homophily of your production network. This module turns the intuition into a
*measurable property of a specific (graph, CVE) pair* that we can then correlate
against observed policy deltas — no synthetic knob required.

Definitions (per CVE c on graph G, with carriers C = carriers(G, c)):

  * ``vulnerable_degree(g, c, v)`` = ``|{w ∈ N_G(v) : w ∈ C}|`` — the number of
    v's neighbours that also carry c (v's degree inside G[C], zero if v ∉ C).
  * ``rank_divergence(g, c)`` = ``1 - Spearman(deg_G(v), vuln_deg_G(v, c)) over
    v ∈ C``. Range [0, 2]. Higher = physical-hub ranking within the carrier set
    disagrees more with the vulnerable-hub ranking. When c is only carried by
    2 hosts or all deg/vuln-deg values are tied, returns ``None``.
  * ``hub_swap(g, c, k)`` = ``1 - Jaccard(top-k by deg_G over all hosts, top-k
    by vuln_deg over carriers)``. Range [0, 1]. Directly measures what fraction
    of the *degree defender's picks* disagrees with the *content-aware picks*
    at budget k.

Direction of the effect is empirical, not axiomatic. In our
``scripts/divergence.py`` sweep across homophily, both metrics correlate
significantly with the per-trial content-aware advantage over degree — the sign
and mechanism are reported honestly in the experiment output, not asserted
here. This module only defines the measurements.
"""

from __future__ import annotations

import networkx as nx
import numpy as np

from serum.inference.identifiability import carriers


def vulnerable_degree(g: nx.Graph, cve: int, v) -> int:
    """Degree of ``v`` inside G[carriers(g, cve)]: how many of v's neighbours
    also carry ``cve``. Zero if v does not carry ``cve``."""
    if cve not in g.nodes[v].get("vuln", frozenset()):
        return 0
    return sum(1 for w in g.neighbors(v)
               if cve in g.nodes[w].get("vuln", frozenset()))


def vulnerable_degrees(g: nx.Graph, cve: int) -> dict:
    """Dict {v: vuln_degree(v, cve)} over all hosts (0 for non-carriers)."""
    C = carriers(g, cve)
    if not C:
        return {v: 0 for v in g.nodes()}
    return {v: (sum(1 for w in g.neighbors(v) if w in C) if v in C else 0)
            for v in g.nodes()}


def _spearman_no_scipy(x: np.ndarray, y: np.ndarray) -> float:
    """Spearman rank correlation via ranked-Pearson; no external dependency
    on scipy (rank helper below). Returns nan on constant input."""
    rx = _rank(x)
    ry = _rank(y)
    if rx.std() < 1e-12 or ry.std() < 1e-12:
        return float("nan")
    return float(np.corrcoef(rx, ry)[0, 1])


def _rank(x: np.ndarray) -> np.ndarray:
    """Average-rank ranking (ties get the mean rank), matches scipy default."""
    x = np.asarray(x, dtype=float)
    order = np.argsort(x, kind="mergesort")
    ranks = np.empty_like(order, dtype=float)
    # walk sorted, assign average rank per tie-block
    i = 0
    n = len(x)
    while i < n:
        j = i + 1
        while j < n and x[order[j]] == x[order[i]]:
            j += 1
        avg = (i + j - 1) / 2.0 + 1.0  # 1-based average rank of positions [i, j-1]
        for k in range(i, j):
            ranks[order[k]] = avg
        i = j
    return ranks


def rank_divergence(g: nx.Graph, cve: int) -> float | None:
    """1 - Spearman(deg_G(v), vuln_deg(v)) over v ∈ carriers(g, cve).

    Returns ``None`` when the carrier set has <3 hosts (correlation
    ill-defined) or when either variable has no rank spread (all-tied)."""
    C = list(carriers(g, cve))
    if len(C) < 3:
        return None
    deg = np.array([g.degree(v) for v in C], dtype=float)
    vd = np.array([sum(1 for w in g.neighbors(v) if w in C) for v in C],
                  dtype=float)
    r = _spearman_no_scipy(deg, vd)
    if np.isnan(r):
        return None
    return float(1.0 - r)


def hub_swap(g: nx.Graph, cve: int, k: int) -> float | None:
    """1 - Jaccard(top-k by deg_G over all hosts, top-k by vuln_deg over
    carriers). A direct operational proxy: at budget k, what fraction of the
    degree defender's top picks the content-aware ranking rejects."""
    C = carriers(g, cve)
    if len(C) < 1 or k < 1:
        return None
    all_nodes = list(g.nodes())
    deg = {v: g.degree(v) for v in all_nodes}
    vd_carriers = {v: sum(1 for w in g.neighbors(v) if w in C) for v in C}
    top_deg = set(sorted(all_nodes, key=lambda v: (-deg[v], str(v)))[:k])
    top_vd = set(sorted(vd_carriers.keys(),
                        key=lambda v: (-vd_carriers[v], str(v)))[:k])
    union = top_deg | top_vd
    if not union:
        return 0.0
    return float(1.0 - len(top_deg & top_vd) / len(union))


def mean_rank_divergence(g: nx.Graph, cves=None,
                         weighted: bool = True) -> float:
    """Fleet-level mean of ``rank_divergence`` across CVEs. Skips CVEs where
    the metric is undefined. If ``weighted`` (default), weights each CVE by
    its prevalence in the fleet — outbreaks proportional to what's out there."""
    if cves is None:
        cves = range(g.graph["n_cves"])
    total = 0.0
    weight = 0.0
    for c in cves:
        d = rank_divergence(g, c)
        if d is None:
            continue
        w = (len(carriers(g, c)) / g.number_of_nodes()) if weighted else 1.0
        total += d * w
        weight += w
    return float(total / weight) if weight > 0 else float("nan")
