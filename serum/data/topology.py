"""Real network topologies with real community structure.

Loads the SNAP email-Eu-core graph (1005 hosts, 42 real departments). The
department labels are ground-truth network *zones*: real organisational units
that, in a real fleet, run similar software. Using them as SERUM's segments
grounds the software-monoculture model in a real community structure rather than
a synthetic partition -- the most realistic setting for the containment
experiments.
"""

from __future__ import annotations

import gzip
import os
import urllib.request

import networkx as nx

SNAP_EDGES = "https://snap.stanford.edu/data/email-Eu-core.txt.gz"
SNAP_DEPTS = "https://snap.stanford.edu/data/email-Eu-core-department-labels.txt.gz"
CACHE = "data/raw/topology"


def _download(url: str, path: str) -> None:
    if os.path.exists(path):
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "serum-research/0.1"})
    with urllib.request.urlopen(req, timeout=60) as r, open(path, "wb") as f:
        f.write(r.read())


def _read_gz_pairs(path: str):
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt") as f:
        for line in f:
            line = line.strip()
            if line:
                a, b = line.split()[:2]
                yield int(a), int(b)


def load_email_eu_core(cache_dir: str = CACHE, largest_cc: bool = True) -> nx.Graph:
    """Load email-Eu-core as an undirected graph whose nodes carry a ``segment``
    attribute (the real department id). Downloads + caches on first use."""
    edges_gz = os.path.join(cache_dir, "email.txt.gz")
    depts_gz = os.path.join(cache_dir, "dept.txt.gz")
    _download(SNAP_EDGES, edges_gz)
    _download(SNAP_DEPTS, depts_gz)

    g = nx.Graph()
    for a, b in _read_gz_pairs(edges_gz):
        if a != b:
            g.add_edge(a, b)
    dept = {int(n): int(d) for n, d in _read_gz_pairs(depts_gz)}

    if largest_cc:
        g = g.subgraph(max(nx.connected_components(g), key=len)).copy()
    # relabel to a contiguous 0..N-1 range, preserving department as "segment"
    order = sorted(g.nodes())
    remap = {old: i for i, old in enumerate(order)}
    h = nx.relabel_nodes(g, remap, copy=True)
    for old, i in remap.items():
        h.nodes[i]["segment"] = dept.get(old, -1)
    h.graph["topology"] = "email-eu-core"
    h.graph["n_departments"] = len({d for _, d in h.nodes(data="segment")})
    return h


def real_segment_map(g: nx.Graph) -> dict:
    """The node -> real department (segment) mapping carried by the graph."""
    return {n: d for n, d in g.nodes(data="segment")}
