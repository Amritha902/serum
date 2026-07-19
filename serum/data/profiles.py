"""Turn cleaned CVEs into realistic per-host vulnerability profiles.

Model. Each host runs a set of *software products* drawn from a real
popularity distribution (estimated from CPE product frequency in the corpus).
A host is vulnerable to CVE *c* iff it runs one of the products *c* affects.
This yields **correlated** vulnerabilities -- hosts running the same product
share CVEs -- which is far more realistic than the independent synthetic Zipf
model, and it makes the vulnerable subgraph structure emerge from real software
co-deployment. Per-CVE transmissibility is derived from the CVSS exploitability
subscore, so "easier" exploits spread faster.

The output plugs directly into the existing simulator: host ``vuln`` frozensets
of integer CVE indices, ``G.graph["n_cves"]``, plus a ``G.graph["vuln_universe"]``
handle exposing per-CVE ids and betas.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field

import networkx as nx
import numpy as np

from serum.data.schema import CVERecord
from serum.sim.network import _base_topology


@dataclass
class RealVulnUniverse:
    products: list                       # software universe (vendor:product)
    weights: np.ndarray                  # deployment popularity over products
    cve_ids: list                        # CVE id per integer index 0..K-1
    cve_products: list                   # set(products) each CVE affects (index-aligned)
    beta: np.ndarray                     # per-CVE transmissibility in [beta_min, beta_max]
    meta: dict = field(default_factory=dict)

    @property
    def n_cves(self) -> int:
        return len(self.cve_ids)


def _cve_beta(rec: CVERecord, beta_min: float, beta_max: float) -> float:
    """Map a CVE's severity to a per-contact transmission probability.

    We use the CVSS base score (0-10, consistent across v2/v3) as a
    version-agnostic transmissibility proxy -- higher-severity, more-exploitable
    vulnerabilities spread more readily -- nudged up for low attack complexity."""
    frac = rec.base_score / 10.0 if rec.base_score >= 0 else 0.5
    if rec.attack_complexity == "LOW":
        frac = min(1.0, frac + 0.1)
    return round(beta_min + frac * (beta_max - beta_min), 4)


def build_universe(
    records,
    n_products: int = 80,
    n_cves: int = 40,
    beta_min: float = 0.08,
    beta_max: float = 0.45,
    rng: np.random.Generator | None = None,
) -> RealVulnUniverse:
    """Select a worm-relevant CVE universe and a software-product distribution."""
    rng = rng or np.random.default_rng()
    worm = [r for r in records if r.is_worm_relevant()]
    if not worm:
        raise ValueError("no worm-relevant CVEs in the corpus "
                         "(need NETWORK vector, no user interaction, >=1 product)")

    freq = Counter(p for r in worm for p in r.products)
    top_products = [p for p, _ in freq.most_common(n_products)]
    pset = set(top_products)

    # keep CVEs that can actually land on a host in our software universe
    cand = [r for r in worm if pset.intersection(r.products)]
    # sample across the natural severity distribution (do NOT take only the most
    # severe, or transmissibility collapses to the maximum); this preserves both
    # the CVSS spread -> a spread of per-CVE beta, and the product-popularity
    # spread -> a spread of prevalence.
    if len(cand) > n_cves:
        idx = rng.choice(len(cand), size=n_cves, replace=False)
        selected = [cand[i] for i in idx]
    else:
        selected = cand

    weights = np.array([freq[p] for p in top_products], dtype=float)
    weights = weights / weights.sum()

    cve_ids = [r.cve_id for r in selected]
    cve_products = [set(r.products) & pset for r in selected]
    beta = np.array([_cve_beta(r, beta_min, beta_max) for r in selected], dtype=float)

    return RealVulnUniverse(
        products=top_products, weights=weights, cve_ids=cve_ids,
        cve_products=cve_products, beta=beta,
        meta={"n_worm_cves": len(worm), "n_candidates": len(cand),
              "beta_range": [beta_min, beta_max]},
    )


def graph_segments(g: nx.Graph, n_segments: int,
                   rng: np.random.Generator) -> dict:
    """Partition the graph into ``n_segments`` *connected* regions via
    multi-source BFS (a graph Voronoi tessellation from random centres).

    Segments model network zones -- subnets, VLANs, OU/imaging groups -- within
    which hosts tend to run the same software. Because each region is connected,
    a shared-software vulnerability induces a connected vulnerable subgraph, so
    a worm can actually traverse it (the realism the independent model lacked)."""
    nodes = list(g.nodes())
    k = max(1, min(n_segments, len(nodes)))
    centers = [int(x) for x in rng.choice(nodes, size=k, replace=False)]
    seg: dict = {}
    dq: deque = deque()
    for i, c in enumerate(centers):
        seg[c] = i
        dq.append(c)
    while dq:  # simultaneous BFS: nearest centre claims each node
        u = dq.popleft()
        for v in g.neighbors(u):
            if v not in seg:
                seg[v] = seg[u]
                dq.append(v)
    for v in nodes:  # any node in a disconnected fragment: assign at random
        if v not in seg:
            seg[v] = int(rng.integers(k))
    return seg


def attach_real_profiles(
    g: nx.Graph,
    universe: RealVulnUniverse,
    products_lambda: float = 6.0,
    n_segments: int = 12,
    homophily: float = 0.75,
    rng: np.random.Generator | None = None,
) -> nx.Graph:
    """Assign each host a real-data-derived vulnerability profile in place.

    ``homophily`` in [0, 1] controls software monoculture: a fraction
    ``homophily`` of a host's products is drawn from its segment's shared
    software image, the rest sampled independently by global popularity.
    ``homophily=0`` recovers the fully-independent assignment (an ablation)."""
    rng = rng or np.random.default_rng()
    prod_index = {p: i for i, p in enumerate(universe.products)}
    cve_prod_idx = [frozenset(prod_index[p] for p in cps) for cps in universe.cve_products]
    n_products = len(universe.products)

    seg = graph_segments(g, n_segments, rng)
    # each segment's shared "software image": a popularity-weighted product set
    image_size = int(min(n_products, max(products_lambda * 3, products_lambda + 4)))
    seg_image: dict = {}
    for s in set(seg.values()):
        img = rng.choice(n_products, size=image_size, replace=False, p=universe.weights)
        seg_image[s] = np.asarray(img)

    for node in g.nodes():
        k = int(min(n_products, max(1, rng.poisson(products_lambda))))
        n_seg = int(round(homophily * k))
        n_glob = k - n_seg
        prods: set = set()
        if n_seg > 0:
            img = seg_image[seg[node]]
            take = min(n_seg, len(img))
            prods.update(int(x) for x in rng.choice(img, size=take, replace=False))
        # top up (segment image exhausted or the independent remainder)
        while len(prods) < k:
            p = int(rng.choice(n_products, p=universe.weights)) if n_glob or not prods \
                else int(rng.choice(seg_image[seg[node]]))
            prods.add(p)
            if len(prods) >= n_products:
                break
        host_products = frozenset(prods)
        vuln = frozenset(i for i, cpi in enumerate(cve_prod_idx) if host_products & cpi)
        g.nodes[node]["vuln"] = vuln
        g.nodes[node]["products"] = host_products
        g.nodes[node]["segment"] = seg[node]

    g.graph["n_cves"] = universe.n_cves
    g.graph["vuln_universe"] = universe
    g.graph["n_segments"] = len(set(seg.values()))
    g.graph["homophily"] = homophily
    g.graph["data_source"] = "nvd"
    return g


def generate_real_network(
    records,
    n: int = 500,
    topology: str = "ba",
    m: int = 3,
    n_products: int = 80,
    n_cves: int = 40,
    products_lambda: float = 6.0,
    n_segments: int = 12,
    homophily: float = 0.75,
    rng: np.random.Generator | None = None,
) -> nx.Graph:
    """Build a topology and attach NVD-derived vulnerability profiles with
    segment-correlated software (monoculture within network zones)."""
    rng = rng or np.random.default_rng()
    g = _base_topology(n, topology, m, rng)
    universe = build_universe(records, n_products=n_products, n_cves=n_cves, rng=rng)
    attach_real_profiles(g, universe, products_lambda=products_lambda,
                         n_segments=n_segments, homophily=homophily, rng=rng)
    g.graph["topology"] = topology
    return g
