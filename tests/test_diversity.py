"""Tests for diversity-for-observability (canary planning)."""
import os
import sys

import networkx as nx
import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from serum.inference.diversity import (
    CanaryPlan, add_canary, apply_plan, greedy_canary_plan,
    identifiability_curve, random_canary_plan, budget_to_full_identifiability,
)
from serum.inference.identifiability import (
    carriers, confusability_graph, is_identifiable, reachable_component,
    support_over,
)


def toy_graph():
    """A hand-built 4-host path where CVE 0 is dominated by CVE 2."""
    g = nx.path_graph(["a", "b", "c", "d"])
    g.nodes["a"]["vuln"] = frozenset({0, 2})
    g.nodes["b"]["vuln"] = frozenset({0, 2})
    g.nodes["c"]["vuln"] = frozenset({0, 2})
    g.nodes["d"]["vuln"] = frozenset({1, 2})
    g.graph["n_cves"] = 3
    return g


def test_singleton_canary_pins_cve_global():
    """A canary with profile {c} makes carriers(c) not a subset of any
    other carriers(c'). So c becomes globally identifiable."""
    g = toy_graph()
    cg = confusability_graph(g)
    assert cg.out_degree(0) > 0  # CVE 0 is confusable (dominated by 2)
    add_canary(g, {0})
    cg2 = confusability_graph(g)
    assert cg2.out_degree(0) == 0
    # AND: adding this canary preserves everything else's identifiability
    assert cg2.out_degree(2) == 0  # 2 was already identifiable


def test_adding_canaries_is_monotone_in_identifiability():
    """Adding canaries can only *grow* carriers(c), which can never introduce
    new subset-order edges — so identifiable_count is non-decreasing."""
    rng = np.random.default_rng(0)
    from serum.sim.network import generate_network
    g = generate_network(n=200, n_cves=14, vuln_lambda=4, popularity_alpha=0.7,
                         rng=rng)
    K = g.graph["n_cves"]
    def _identifiable_global(h):
        cg = confusability_graph(h)
        live = [c for c in range(K) if carriers(h, c)]
        return sum(1 for c in live if cg.out_degree(c) == 0)
    counts = [_identifiable_global(g)]
    plan = greedy_canary_plan(g, budget=8, mode="global")
    for i in range(1, len(plan) + 1):
        h = apply_plan(g, CanaryPlan(plan.entries[:i]))
        counts.append(_identifiable_global(h))
    assert all(a <= b for a, b in zip(counts, counts[1:])), (
        f"monotonicity violated: {counts}")


def test_operational_canary_pins_via_reachable_component():
    """An operational-mode canary attached to a host in R(c) folds into the
    saturating outbreak. The augmented reachable component now contains the
    canary; its vuln = {c}, so supp(R_aug) ⊆ {c} and c is operationally
    identifiable."""
    g = toy_graph()
    # CVE 0's reachable component is {a, b, c} — all have vuln {0, 2}, so
    # supp(R) = {0, 2}: CVE 0 is NOT operationally identifiable, confuser 2.
    assert not is_identifiable(g, 0)
    plan = greedy_canary_plan(g, budget=1, mode="operational")
    # the greedy planner should pick CVE 0 (or another unidentifiable one)
    # and attach to some host in that CVE's reachable component
    h = apply_plan(g, plan)
    # after augmentation, at least one previously-unidentifiable CVE is now
    # operationally identifiable (monotone + progress)
    ident_before = sum(1 for c in range(g.graph["n_cves"])
                       if carriers(g, c) and is_identifiable(g, c))
    ident_after = sum(1 for c in range(h.graph["n_cves"])
                      if carriers(h, c) and is_identifiable(h, c))
    assert ident_after > ident_before


def test_greedy_reaches_100_percent_with_enough_budget():
    """With K_live canaries (a singleton per live CVE), we can pin every live
    CVE. The greedy planner terminates early once nothing more is unidentifiable."""
    from serum.sim.network import generate_network
    g = generate_network(n=200, n_cves=14, vuln_lambda=4, popularity_alpha=0.7,
                         rng=np.random.default_rng(0))
    K = g.graph["n_cves"]
    live = sum(1 for c in range(K) if carriers(g, c))
    B_full = budget_to_full_identifiability(g, mode="global", max_budget=2 * K)
    assert B_full <= live
    h = apply_plan(g, greedy_canary_plan(g, budget=B_full, mode="global"))
    cg = confusability_graph(h)
    live_h = [c for c in range(K) if carriers(h, c)]
    assert all(cg.out_degree(c) == 0 for c in live_h)


def test_greedy_beats_or_matches_random_on_average():
    """The optimality argument (module docstring) implies greedy adds one
    guaranteed identifiable CVE per canary until saturation. Random singletons
    can duplicate CVEs across canaries, so on average they under-pin. Verify
    on a real-ish synthetic setup: mean_greedy >= mean_random at every B."""
    from serum.sim.network import generate_network
    means_g, means_r = {b: [] for b in [1, 2, 4, 8]}, {b: [] for b in [1, 2, 4, 8]}
    for seed in range(6):
        g = generate_network(n=250, n_cves=16, vuln_lambda=5, popularity_alpha=0.7,
                             rng=np.random.default_rng(seed))
        curve_g = identifiability_curve(g, [1, 2, 4, 8], mode="global", strategy="greedy")
        curve_r = identifiability_curve(g, [1, 2, 4, 8], mode="global", strategy="random",
                                        rng=np.random.default_rng(seed))
        for row_g, row_r in zip(curve_g, curve_r):
            means_g[row_g["B"]].append(row_g["identifiable_fraction"])
            means_r[row_r["B"]].append(row_r["identifiable_fraction"])
    for B in [1, 2, 4, 8]:
        assert np.mean(means_g[B]) >= np.mean(means_r[B]) - 1e-9, (
            f"B={B}: greedy_mean={np.mean(means_g[B]):.3f} < "
            f"random_mean={np.mean(means_r[B]):.3f}")


def test_canary_profile_out_of_range_raises():
    g = toy_graph()
    with pytest.raises(ValueError):
        add_canary(g, {99})


def test_canary_attach_to_missing_node_raises():
    g = toy_graph()
    with pytest.raises(ValueError):
        add_canary(g, {0}, attach_to="ghost")
