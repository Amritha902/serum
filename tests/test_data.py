"""Tests for the NVD ingestion + cleaning + profile pipeline.

Uses hand-built raw records shaped like the NVD 2.0 API so the cleaning logic is
tested deterministically with no network access.
"""
import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from serum.data.clean import clean_records, parse_record
from serum.data.profiles import attach_real_profiles, build_universe, generate_real_network
from serum.data.schema import AttackVector, CVERecord
from serum.sim.network import _base_topology, cve_prevalence


def raw(cve_id, av="NETWORK", ui="NONE", ac="LOW", score=9.8, ver="v31",
        products=(("a", "vendorx", "productx"),), rejected=False, no_metrics=False,
        exploit=3.9):
    cpe = [{"criteria": f"cpe:2.3:{p[0]}:{p[1]}:{p[2]}:1.0:*:*:*:*:*:*:*",
            "vulnerable": True} for p in products]
    cve = {
        "id": cve_id,
        "published": "2023-05-01T00:00:00.000",
        "vulnStatus": "Rejected" if rejected else "Analyzed",
        "descriptions": [{"lang": "en", "value": "test"}],
        "configurations": [{"nodes": [{"cpeMatch": cpe}]}],
        "metrics": {},
    }
    if not no_metrics:
        key = {"v31": "cvssMetricV31", "v30": "cvssMetricV30", "v2": "cvssMetricV2"}[ver]
        data = {"baseScore": score, "attackVector": av, "attackComplexity": ac,
                "privilegesRequired": "NONE", "userInteraction": ui,
                "baseSeverity": "CRITICAL"}
        if ver == "v2":
            data = {"baseScore": score, "accessVector": av, "accessComplexity": ac}
        cve["metrics"][key] = [{"cvssData": data, "exploitabilityScore": exploit}]
    return cve


def test_parse_prefers_v31_and_extracts_fields():
    rec = parse_record(raw("CVE-2023-0001"))
    assert rec.cvss_version == "3.1"
    assert rec.attack_vector == AttackVector.NETWORK
    assert rec.base_score == 9.8
    assert rec.products == ("vendorx:productx",)


def test_clean_filters_rejected_and_no_metrics_and_dedup():
    raws = [
        raw("CVE-A"),
        raw("CVE-A"),                      # duplicate
        raw("CVE-B", rejected=True),       # rejected
        raw("CVE-C", no_metrics=True),     # no CVSS
        raw("CVE-D", av="LOCAL"),          # kept but not worm-relevant
    ]
    records, stats = clean_records(raws)
    ids = {r.cve_id for r in records}
    assert ids == {"CVE-A", "CVE-D"}
    assert stats.duplicate == 1
    assert stats.rejected == 1
    assert stats.no_metrics == 1
    assert stats.kept == 2


def test_worm_relevance_requires_network_vector_and_no_user_interaction():
    assert parse_record(raw("CVE-1", av="NETWORK", ui="NONE")).is_worm_relevant()
    assert not parse_record(raw("CVE-2", av="LOCAL")).is_worm_relevant()
    assert not parse_record(raw("CVE-3", av="NETWORK", ui="REQUIRED")).is_worm_relevant()


def test_v2_record_parsed():
    rec = parse_record(raw("CVE-old", ver="v2", av="NETWORK", score=7.5))
    assert rec.cvss_version == "2.0"
    assert rec.attack_vector == AttackVector.NETWORK


def _corpus(n=60):
    # a spread of products so prevalence varies; a few popular, many rare
    recs = []
    for i in range(n):
        pop = "core:os" if i % 3 == 0 else f"vend{i}:prod{i}"
        recs.append(parse_record(raw(f"CVE-X-{i}", products=((("a",) + tuple(pop.split(":"))),),
                                     score=5 + (i % 5))))
    return [r for r in recs if r is not None]


def test_build_universe_and_profiles_are_valid():
    records = _corpus()
    uni = build_universe(records, n_products=20, n_cves=15, rng=np.random.default_rng(0))
    assert uni.n_cves <= 15
    assert uni.beta.min() >= 0.05 and uni.beta.max() <= 0.5
    g = _base_topology(200, "ba", 3, np.random.default_rng(1))
    attach_real_profiles(g, uni, n_segments=8, homophily=0.5, rng=np.random.default_rng(2))
    assert g.graph["n_cves"] == uni.n_cves
    assert all("vuln" in d and "segment" in d for _, d in g.nodes(data=True))
    prev = cve_prevalence(g)
    assert prev.min() >= 0.0 and prev.max() <= 1.0


def test_segments_are_connected_regions():
    """Each graph segment must be a connected subgraph (a real network zone)."""
    import networkx as nx
    from serum.data.profiles import graph_segments
    g = _base_topology(300, "ba", 3, np.random.default_rng(4))
    seg = graph_segments(g, 10, np.random.default_rng(5))
    assert set(seg) == set(g.nodes())
    for s in set(seg.values()):
        members = [n for n, sg in seg.items() if sg == s]
        assert nx.is_connected(g.subgraph(members)), f"segment {s} not connected"


def test_homophily_raises_within_segment_software_sharing():
    """Higher homophily => neighbours in the same segment share more products."""
    records = _corpus(80)
    uni = build_universe(records, n_products=30, n_cves=20, rng=np.random.default_rng(0))

    def mean_shared(hom):
        g = _base_topology(300, "ba", 3, np.random.default_rng(1))
        attach_real_profiles(g, uni, n_segments=10, homophily=hom,
                             rng=np.random.default_rng(2))
        vals = []
        for u, v in g.edges():
            if g.nodes[u]["segment"] == g.nodes[v]["segment"]:
                a, b = g.nodes[u]["products"], g.nodes[v]["products"]
                vals.append(len(a & b) / max(1, len(a | b)))
        return np.mean(vals) if vals else 0.0

    assert mean_shared(0.9) > mean_shared(0.0)


def test_generate_real_network_end_to_end():
    records = _corpus(80)
    g = generate_real_network(records, n=150, n_cves=12, n_products=25,
                              rng=np.random.default_rng(3))
    assert g.number_of_nodes() == 150
    assert g.graph["data_source"] == "nvd"
    assert g.graph["n_cves"] == 12


def test_threat_intel_prior_and_agent():
    """The threat-intel prior weights are a valid distribution and the agent
    runs end-to-end on a real-data network."""
    from serum.agents.threat_intel import ThreatIntelAgent, threat_intel_weights
    from serum.inference.belief import CVEBelief
    records = _corpus(80)
    g = generate_real_network(records, n=200, n_cves=12, n_products=25,
                              rng=np.random.default_rng(3))
    w = threat_intel_weights(g.graph["vuln_universe"])
    assert abs(w.sum() - 1.0) < 1e-6 and (w >= 0).all()
    # belief accepts the threat_intel prior; agent constructs and is callable
    b = CVEBelief(g, prior="threat_intel")
    assert abs(b.posterior().sum() - 1.0) < 1e-6
    agent = ThreatIntelAgent(g)
    assert agent.name == "content-aware+intel"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))


def test_real_topology_loads_with_segments():
    """email-Eu-core loads as a connected graph whose nodes carry real
    department segments. Skips gracefully if the data isn't available."""
    import pytest
    try:
        from serum.data.topology import load_email_eu_core
        g = load_email_eu_core()
    except Exception as e:
        pytest.skip(f"real topology unavailable: {e}")
    import networkx as nx
    assert g.number_of_nodes() > 900
    assert nx.is_connected(g)
    assert all("segment" in g.nodes[n] for n in g.nodes())
    assert g.graph["n_departments"] > 1


def test_imperfect_inventory_defender_view():
    """apply_inventory_noise creates a defender view that (a) differs from truth
    and (b) misses some true vulns; defender_vuln falls back to truth otherwise."""
    from serum.data.inventory import apply_inventory_noise, defender_vuln
    records = _corpus(80)
    g = generate_real_network(records, n=300, n_cves=20, n_products=40,
                              rng=np.random.default_rng(3))
    # before noise: defender_vuln == ground truth
    v0 = next(iter(g.nodes()))
    assert defender_vuln(g, v0) == g.nodes[v0]["vuln"]
    apply_inventory_noise(g, miss=0.5, false=0.0, rng=np.random.default_rng(1))
    # with 50% miss and no false entries, observed is a strict-ish subset of truth
    missed = sum(len(g.nodes[v]["vuln"]) - len(g.nodes[v]["vuln_observed"])
                 for v in g.nodes())
    assert missed > 0
    for v in g.nodes():
        assert g.nodes[v]["vuln_observed"] <= g.nodes[v]["vuln"]  # miss-only => subset
