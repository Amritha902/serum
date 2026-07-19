"""Tests for the exploit-identifiability theory (docs/THEORY.md)."""
import os
import sys

import networkx as nx
import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from serum.inference.belief import CVEBelief
from serum.inference.identifiability import (
    carriers, confusability_graph, confusers, identifiable_fraction,
    is_identifiable, reachable_component, support_over,
)


def toy_graph():
    """A hand-built 4-host path with known profiles.

    Universe = {0,1,2}. Profiles chosen so that:
      - CVE 0 carriers = {a,b,c} (a connected path)  -> its victims all also
        carry CVE 2, so 0 is NOT identifiable (confuser 2).
      - CVE 1 carriers = {d} only.
      - CVE 2 carriers = {a,b,c,d} (everyone) -> superset of 0's carriers.
    """
    g = nx.path_graph(["a", "b", "c", "d"])
    g.nodes["a"]["vuln"] = frozenset({0, 2})
    g.nodes["b"]["vuln"] = frozenset({0, 2})
    g.nodes["c"]["vuln"] = frozenset({0, 2})
    g.nodes["d"]["vuln"] = frozenset({1, 2})
    g.graph["n_cves"] = 3
    return g


def test_support_is_intersection():
    g = toy_graph()
    assert support_over(g, ["a", "b", "c"]) == {0, 2}
    assert support_over(g, ["a", "d"]) == {2}


def test_carriers_and_components():
    g = toy_graph()
    assert carriers(g, 0) == {"a", "b", "c"}
    assert carriers(g, 2) == {"a", "b", "c", "d"}
    assert reachable_component(g, 0) == {"a", "b", "c"}


def test_identifiability_matches_theory():
    g = toy_graph()
    # CVE 0's victims all carry 2 -> not identifiable, confuser {2}
    assert not is_identifiable(g, 0)
    assert confusers(g, 0) == {2}
    # CVE 2 is carried by everyone but no other CVE is a superset -> identifiable
    assert is_identifiable(g, 2)
    assert confusers(g, 2) == set()


def test_confusability_graph_is_subset_order():
    g = toy_graph()
    h = confusability_graph(g)
    assert h.has_edge(0, 2)          # carriers(0) subset carriers(2)
    assert not h.has_edge(2, 0)      # not the reverse
    # globally identifiable CVEs = no out-neighbours
    ident = [c for c in h.nodes() if h.out_degree(c) == 0]
    assert 2 in ident and 0 not in ident


def test_belief_matches_theorem_on_toy():
    """The hard belief's converged support must equal supp(R) (Prop 1-2)."""
    g = toy_graph()
    belief = CVEBelief(g, mode="hard", known_seeds=False)
    # observe the full CVE-0 component
    belief.update({"a", "b", "c"}, frozenset())
    post = belief.posterior()
    support = {c for c in range(3) if post[c] > 0}
    assert support == support_over(g, ["a", "b", "c"]) == {0, 2}


def test_identifiable_fraction_in_unit_interval():
    g = toy_graph()
    f = identifiable_fraction(g)
    assert 0.0 <= f <= 1.0


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))


def test_evasive_payload_is_confusable_but_spreads():
    """The evasive attacker picks a spreading, non-identifiable payload; a
    'spread' attacker maximises reach. Both must return a valid CVE."""
    from serum.attack.adversarial import select_payload, payload_identifiability_score
    g = toy_graph()
    # CVE 0 spreads (component {a,b,c}) and is confusable (confuser 2) -> evasive pick
    ev = select_payload(g, beta=0.3, objective="evasive", min_component=2)
    assert ev.cve in range(3)
    score = payload_identifiability_score(g, 0)
    assert score["n_confusers"] == 1 and not score["identifiable"]
