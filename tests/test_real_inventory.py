"""The real-inventory adapter (L1 readiness): host->CVE is taken VERBATIM.

The single property that distinguishes this from the modeled generators, and the
reason it can close L1 when fed real data: each host's vulnerability set equals
exactly what the scan reported -- nothing is sampled, popularity-weighted, or
zone-assigned. These tests pin that, plus the CSV parsing and the graph contract
the rest of SERUM depends on.
"""
from __future__ import annotations

import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from serum.agents.content_aware import ContentAwareAgent
from serum.data.real_inventory import build_inventory_network, load_scan_network
from serum.sim.environment import ContainmentEnv
from serum.sim.payload import Payload


def test_vuln_is_measured_verbatim():
    scan = [("h1", "CVE-2024-0001"), ("h1", "CVE-2024-0002"),
            ("h2", "CVE-2024-0002"), ("h3", "CVE-2024-0009")]
    edges = [("h1", "h2"), ("h2", "h3")]
    g = build_inventory_network(scan, edges)
    idx = {v: k for k, v in g.graph["cve_ids"].items()}   # real id -> index
    # h1 carries exactly its two scanned CVEs, h2 exactly one, h3 exactly one
    assert g.nodes["h1"]["vuln"] == frozenset({idx["CVE-2024-0001"], idx["CVE-2024-0002"]})
    assert g.nodes["h2"]["vuln"] == frozenset({idx["CVE-2024-0002"]})
    assert g.nodes["h3"]["vuln"] == frozenset({idx["CVE-2024-0009"]})
    assert g.graph["n_cves"] == 3
    assert g.graph["data_source"] == "measured-scan"


def test_host_in_topology_without_findings_has_empty_vuln():
    scan = [("h1", "CVE-A")]
    edges = [("h1", "h2"), ("h2", "h3")]         # h2, h3 have no scan findings
    g = build_inventory_network(scan, edges)
    assert g.nodes["h2"]["vuln"] == frozenset()
    assert g.nodes["h3"]["vuln"] == frozenset()
    assert set(g.nodes()) == {"h1", "h2", "h3"}
    assert g.has_edge("h1", "h2") and g.has_edge("h2", "h3")


def test_csv_parsing_with_alternate_column_names(tmp_path):
    scan_csv = tmp_path / "scan.csv"
    scan_csv.write_text("asset_id,plugin_cve,severity\n"
                        "10.0.0.1,CVE-2023-1,high\n"
                        "10.0.0.1,CVE-2023-2,med\n"
                        "10.0.0.2,CVE-2023-1,high\n")
    edges = tmp_path / "edges.csv"
    edges.write_text("10.0.0.1,10.0.0.2\n# a comment line\n10.0.0.2 10.0.0.3\n")
    g = load_scan_network(str(scan_csv), str(edges))
    assert g.number_of_nodes() == 3          # .1, .2, .3 (.3 only in edges)
    assert g.graph["n_cves"] == 2
    idx = {v: k for k, v in g.graph["cve_ids"].items()}
    assert g.nodes["10.0.0.1"]["vuln"] == frozenset({idx["CVE-2023-1"], idx["CVE-2023-2"]})
    assert g.nodes["10.0.0.3"]["vuln"] == frozenset()


def test_loaded_network_runs_an_episode():
    """The graph contract must satisfy the env + content-aware agent unchanged."""
    rng = np.random.default_rng(0)
    scan, edges = [], []
    # 40 hosts, 8 CVEs, a ring+chords topology, so an outbreak can actually spread
    for v in range(40):
        for c in rng.choice(8, size=2, replace=False):
            scan.append((f"h{v}", f"CVE-{int(c)}"))
    for v in range(40):
        edges.append((f"h{v}", f"h{(v + 1) % 40}"))
        edges.append((f"h{v}", f"h{(v + 7) % 40}"))
    g = build_inventory_network(scan, edges)
    # pick a CVE some hosts carry, seed among its carriers
    cve = 0
    carriers = [v for v in g.nodes() if cve in g.nodes[v]["vuln"]]
    assert carriers, "fixture should have carriers of CVE index 0"
    env = ContainmentEnv(g=g, payload=Payload(cve=cve, beta=0.5),
                         seeds=carriers[:2], budget_per_step=3, horizon=20,
                         rng=np.random.default_rng(1))
    res = env.run(ContentAwareAgent(g))
    assert 0.0 <= res.infected_fraction <= 1.0
