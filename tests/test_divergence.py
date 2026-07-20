"""Tests for the zone-hub divergence metric (SR2)."""

from __future__ import annotations

import json
import os

import networkx as nx
import numpy as np
import pytest

from serum.inference.divergence import (
    _rank,
    _spearman_no_scipy,
    hub_swap,
    mean_rank_divergence,
    rank_divergence,
    vulnerable_degree,
    vulnerable_degrees,
)


def _star_graph_with_profiles(vulns):
    """Star centred at 0 with n leaves; ``vulns`` is a list of frozensets
    length n+1 (index 0 is the centre). ``n_cves`` derived from the max id + 1."""
    g = nx.Graph()
    for i, v in enumerate(vulns):
        g.add_node(i, vuln=frozenset(v))
    for i in range(1, len(vulns)):
        g.add_edge(0, i)
    g.graph["n_cves"] = max(max(v) for v in vulns if v) + 1
    return g


def test_rank_helper_matches_scipy_avg_ranking():
    """Our _rank uses average-of-tied-positions, the scipy default."""
    x = np.array([10, 20, 10, 30, 20], dtype=float)
    r = _rank(x)
    # 10s occupy ranks 1,2 -> avg 1.5; 20s occupy 3,4 -> avg 3.5; 30 -> 5
    np.testing.assert_allclose(r, [1.5, 3.5, 1.5, 5.0, 3.5])


def test_spearman_matches_scipy_on_random_input():
    scipy_stats = pytest.importorskip("scipy.stats")
    rng = np.random.default_rng(1)
    for _ in range(5):
        a = rng.normal(size=50)
        b = rng.normal(size=50)
        r_ours = _spearman_no_scipy(a, b)
        r_scipy = scipy_stats.spearmanr(a, b).statistic
        assert abs(r_ours - r_scipy) < 1e-9


def test_vulnerable_degree_zero_for_non_carrier():
    g = _star_graph_with_profiles([{0}, {0}, {1}, {1}])
    # node 2 does NOT carry CVE 0 -> vulnerable_degree(g, 0, 2) == 0
    assert vulnerable_degree(g, 0, 2) == 0
    # node 0 (centre) carries CVE 0 and has one neighbour (node 1) that also
    # carries CVE 0 -> vulnerable_degree == 1 (node 2 and node 3 do not carry it)
    assert vulnerable_degree(g, 0, 0) == 1
    # vulnerable_degrees returns 0 for non-carriers across the fleet
    vd = vulnerable_degrees(g, 0)
    assert vd[2] == 0 and vd[3] == 0
    assert vd[0] == 1 and vd[1] == 1


def test_rank_divergence_returns_none_when_carrier_set_too_small():
    # only two carriers: correlation ill-defined -> None
    g = _star_graph_with_profiles([{0}, {0}, {1}, {1}])
    assert rank_divergence(g, 0) is None


def test_rank_divergence_returns_none_when_all_tied():
    # Regular graph of 5 nodes all carrying CVE 0 -> every host has same deg
    # and same vuln_deg -> ranks tied everywhere -> None (not spurious 1.0).
    g = nx.cycle_graph(5)
    for v in g.nodes():
        g.nodes[v]["vuln"] = frozenset({0})
    g.graph["n_cves"] = 1
    assert rank_divergence(g, 0) is None


def test_rank_divergence_low_when_deg_and_vuln_deg_align():
    """Physical hub is also the vulnerable-degree hub -> Spearman ~ 1, div ~ 0.
    Build a star + attached triangle: centre has both high deg and high vuln_deg."""
    g = nx.Graph()
    # centre 0 + 5 leaves all carrying CVE 0
    for i in range(6):
        g.add_node(i, vuln=frozenset({0}))
    for i in range(1, 6):
        g.add_edge(0, i)
    # add extra edges among leaves so ranks are not all tied
    g.add_edge(1, 2)
    g.add_edge(3, 4)
    g.graph["n_cves"] = 1
    d = rank_divergence(g, 0)
    assert d is not None
    # centre has highest deg AND highest vuln_deg -> positive Spearman -> low div
    assert d < 0.5, f"expected low divergence when hubs align, got {d}"


def test_rank_divergence_high_when_deg_and_vuln_deg_disagree():
    """Build a graph where the physical hub is NOT the vulnerable hub.
    Centre has many neighbours but almost none carry the CVE; a leaf-cluster
    carries the CVE among themselves. Rank order disagrees -> divergence > 1."""
    g = nx.Graph()
    # centre carrying CVE 0, 10 leaves NOT carrying CVE 0
    g.add_node(0, vuln=frozenset({0}))
    for i in range(1, 11):
        g.add_node(i, vuln=frozenset({1}))
        g.add_edge(0, i)
    # a small carrier cluster connected only weakly to centre
    for j in range(11, 15):
        g.add_node(j, vuln=frozenset({0}))
    for a in range(11, 15):
        for b in range(a + 1, 15):
            g.add_edge(a, b)
    g.add_edge(0, 11)  # thin bridge
    g.graph["n_cves"] = 2
    d = rank_divergence(g, 0)
    assert d is not None
    # centre has huge deg but small vuln_deg (=1); cluster nodes have small deg
    # but vuln_deg=3 among themselves -> rank order flipped -> d > 1
    assert d > 1.0, f"expected divergence > 1 when hubs anti-correlate, got {d}"


def test_hub_swap_zero_when_top_sets_coincide():
    # Star where centre has highest deg AND highest vuln_deg;
    # at k=1 top-1 sets must coincide -> hub_swap == 0
    g = nx.Graph()
    for i in range(6):
        g.add_node(i, vuln=frozenset({0}))
    for i in range(1, 6):
        g.add_edge(0, i)
    g.graph["n_cves"] = 1
    assert hub_swap(g, 0, k=1) == 0.0


def test_hub_swap_one_when_top_sets_disjoint():
    # A graph where the top-1 by degree is NOT a carrier; top-1 by vuln_deg is;
    # they are disjoint so hub_swap == 1.
    g = nx.Graph()
    g.add_node(0, vuln=frozenset({1}))    # centre, huge degree, no CVE 0
    for i in range(1, 6):
        g.add_node(i, vuln=frozenset({1}))
        g.add_edge(0, i)
    # small connected carrier cluster
    for j in range(6, 9):
        g.add_node(j, vuln=frozenset({0}))
    g.add_edge(6, 7); g.add_edge(7, 8); g.add_edge(6, 8)
    g.graph["n_cves"] = 2
    assert hub_swap(g, 0, k=1) == 1.0


def test_mean_rank_divergence_weighted_and_none_skipping():
    """Weighted mean prevalence-weights each CVE; CVEs where the metric is
    undefined are silently skipped."""
    # CVE 0 has 4 well-connected carriers with varied vuln_deg (defined).
    # CVE 1 has 1 carrier (rank_divergence returns None) -> silently skipped.
    g = nx.Graph()
    g.add_node(0, vuln=frozenset({0}))
    g.add_node(1, vuln=frozenset({0}))
    g.add_node(2, vuln=frozenset({0}))
    g.add_node(3, vuln=frozenset({0}))
    g.add_node(4, vuln=frozenset({1}))    # sole CVE-1 carrier
    # spanning edges among CVE-0 carriers to give varying vuln_deg (0-hub,
    # 1-hub-with-leaves)
    g.add_edges_from([(0, 1), (0, 2), (0, 3), (1, 2), (0, 4)])
    g.graph["n_cves"] = 2
    d0 = rank_divergence(g, 0)
    assert d0 is not None, "CVE 0 rank_divergence should be defined"
    m = mean_rank_divergence(g)
    # Only CVE 0 is defined, so weighted mean == its own value (weight cancels)
    assert m == d0


def test_experiment_result_hypothesis_holds_when_artifact_exists():
    """If the experiment has been run, verify the reported pooled correlation
    matches what the raw per-trial data actually implies. Cross-check against
    the paper claim that the divergence metric significantly predicts delta."""
    path = "results/divergence.json"
    if not os.path.exists(path):
        pytest.skip("results/divergence.json not present; skipping cross-check")
    data = json.loads(open(path).read())
    rows = data.get("per_trial", [])
    if len(rows) < 20:
        pytest.skip("too few trials to cross-check")
    divs = np.array([r["div_rank"] for r in rows], dtype=float)
    deltas = np.array([r["delta"] for r in rows], dtype=float)
    r_recompute = _spearman_no_scipy(divs, deltas)
    r_reported = data["pooled_spearman"]["div_rank_vs_delta"]["r"]
    assert abs(r_recompute - r_reported) < 1e-6, \
        f"reported r={r_reported} vs recomputed r={r_recompute} disagree"
    # Direction sanity: pilot found NEGATIVE correlation in this regime.
    # If a future run reverses direction, we prefer to fail loudly and update
    # the paper narrative rather than silently ship an inconsistent claim.
    assert r_recompute < 0.0, (
        f"divergence-delta Spearman flipped sign to {r_recompute:+.3f}; "
        "update the DEVLOG/paper before dismissing this test"
    )
