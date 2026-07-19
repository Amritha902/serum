"""Heterogeneous host networks with realistic vulnerability profiles.

Each node is a host carrying a *software bill of vulnerabilities*: the set of
CVEs it is exploitable by. CVE prevalence across the fleet is heavy-tailed
(a few very common services, a long tail of rare ones), mirroring real
enterprise inventories. This heterogeneity is the whole point: a payload can
only traverse edges into hosts that carry its target CVE, so the *effective*
propagation graph is a payload-specific subgraph of the physical topology.
"""

from __future__ import annotations

import networkx as nx
import numpy as np


def _base_topology(n: int, topology: str, m: int, rng: np.random.Generator) -> nx.Graph:
    seed = int(rng.integers(0, 2**31 - 1))
    if topology == "ba":  # Barabasi-Albert scale-free (Internet-like hubs)
        return nx.barabasi_albert_graph(n, m, seed=seed)
    if topology == "ws":  # Watts-Strogatz small-world (enterprise LAN-like)
        return nx.watts_strogatz_graph(n, k=max(2, 2 * m), p=0.1, seed=seed)
    if topology == "er":  # Erdos-Renyi (null model)
        return nx.gnp_random_graph(n, p=min(1.0, 2.0 * m / n), seed=seed)
    if topology == "rgg":  # random geometric (physical proximity / IoT)
        radius = (m / (np.pi * n)) ** 0.5 * 2.0
        g = nx.random_geometric_graph(n, radius, seed=seed)
        # ensure connectivity by linking components to the giant one
        comps = list(nx.connected_components(g))
        giant = max(comps, key=len)
        for comp in comps:
            if comp is giant:
                continue
            g.add_edge(next(iter(comp)), next(iter(giant)))
        return g
    raise ValueError(f"unknown topology: {topology!r}")


def generate_network(
    n: int = 500,
    topology: str = "ba",
    m: int = 3,
    n_cves: int = 24,
    vuln_lambda: float = 3.0,
    popularity_alpha: float = 1.3,
    rng: np.random.Generator | None = None,
) -> nx.Graph:
    """Generate a host graph with heavy-tailed per-host vulnerability profiles.

    Parameters
    ----------
    n : number of hosts.
    topology : one of {"ba", "ws", "er", "rgg"}.
    m : density parameter (attachment / neighbourhood size).
    n_cves : size of the CVE universe.
    vuln_lambda : mean number of CVEs per host (Poisson, clamped to >=1).
    popularity_alpha : Zipf exponent of CVE prevalence (higher = more skewed).

    Returns
    -------
    networkx.Graph whose nodes carry a ``vuln`` attribute: a frozenset of CVE
    ids. ``G.graph["n_cves"]`` records the universe size.
    """
    rng = rng or np.random.default_rng()
    g = _base_topology(n, topology, m, rng)

    # Zipf-like popularity weights over the CVE universe.
    ranks = np.arange(1, n_cves + 1)
    popularity = 1.0 / ranks**popularity_alpha
    popularity /= popularity.sum()

    for node in g.nodes():
        k = int(min(n_cves, max(1, rng.poisson(vuln_lambda))))
        cves = rng.choice(n_cves, size=k, replace=False, p=popularity)
        g.nodes[node]["vuln"] = frozenset(int(c) for c in cves)

    g.graph["n_cves"] = int(n_cves)
    g.graph["topology"] = topology
    return g


def assign_criticality(
    g: nx.Graph,
    alpha: float = 1.5,
    value_max: float = 20.0,
    cost_scales_with_value: bool = True,
    rng: np.random.Generator | None = None,
) -> nx.Graph:
    """Attach heavy-tailed criticality to every host, in place.

    Real fleets are lopsided: most hosts are commodity endpoints, a small
    minority (crown-jewel databases, domain controllers, payment gateways) matter
    disproportionately. We draw ``value(v)`` from a Zipf-like tail so a few
    hosts dominate the *blast radius* of any outbreak, and set the isolation
    cost ``cost_isolate(v)`` in proportion (taking a critical host offline hurts
    more than isolating a laptop).

    Parameters
    ----------
    alpha : shape of the value tail (Pareto exponent + 1). Higher = flatter,
        lower = more skew. 1.5 gives a moderately heavy tail.
    value_max : cap on any single host's value (avoid runaway outliers).
    cost_scales_with_value : if True, ``cost_isolate = value``. Otherwise
        every host has cost 1 (so budget = action count as before).

    The network's total value is stored on ``g.graph["total_value"]`` and total
    isolation cost on ``g.graph["total_cost"]`` for downstream metrics.
    """
    rng = rng or np.random.default_rng()
    total_value = 0.0
    total_cost = 0.0
    for v in g.nodes():
        # Pareto tail, shifted so minimum value is 1.0.
        val = 1.0 + rng.pareto(alpha)
        val = float(min(val, value_max))
        g.nodes[v]["value"] = val
        cost = val if cost_scales_with_value else 1.0
        g.nodes[v]["cost_isolate"] = float(cost)
        total_value += val
        total_cost += cost
    g.graph["total_value"] = float(total_value)
    g.graph["total_cost"] = float(total_cost)
    return g


def total_value(g: nx.Graph) -> float:
    """Sum of host ``value`` attributes, defaulting to n if unset."""
    if "total_value" in g.graph:
        return float(g.graph["total_value"])
    return float(sum(d.get("value", 1.0) for _, d in g.nodes(data=True)))


def total_cost(g: nx.Graph) -> float:
    """Sum of host ``cost_isolate`` attributes, defaulting to n if unset."""
    if "total_cost" in g.graph:
        return float(g.graph["total_cost"])
    return float(sum(d.get("cost_isolate", 1.0) for _, d in g.nodes(data=True)))


def cve_prevalence(g: nx.Graph) -> np.ndarray:
    """Return the fraction of hosts vulnerable to each CVE id."""
    n_cves = g.graph["n_cves"]
    counts = np.zeros(n_cves, dtype=float)
    for _, data in g.nodes(data=True):
        for c in data["vuln"]:
            counts[c] += 1.0
    return counts / g.number_of_nodes()


def vulnerable_subgraph(g: nx.Graph, cve: int) -> nx.Graph:
    """The subgraph induced by hosts exploitable by ``cve`` -- the true
    propagation surface for a payload targeting that vulnerability."""
    nodes = [n for n, d in g.nodes(data=True) if cve in d["vuln"]]
    return g.subgraph(nodes)
