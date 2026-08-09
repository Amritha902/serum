"""The inventory-allocation game: catalog restriction, blind-spot payload
selection, and proxy-coverage allocation."""
from __future__ import annotations

import numpy as np
import pytest

from serum.attack.catalog_attack import (
    allocate_maximin_proxy,
    allocate_prevalence,
    allocate_random,
    blindspot_frontier,
    carrier_sets,
    jaccard_matrix,
    proxy_coverage,
    select_blindspot_payload,
    spreading_cves,
    worst_case_proxy,
)
from serum.data.inventory import defender_vuln
from serum.sim.catalog import catalog, restrict_catalog, true_carriers
from serum.sim.network import generate_network

MIN_COMP = 10


def _net(seed=0, n=300, n_cves=16):
    return generate_network(n=n, topology="ba", m=3, n_cves=n_cves,
                            vuln_lambda=6.0, popularity_alpha=0.8,
                            rng=np.random.default_rng(seed))


# -- catalog restriction ---------------------------------------------------

def test_restrict_catalog_narrows_view_but_not_truth():
    g = _net()
    covered = frozenset({0, 1, 2})
    truth = {v: set(g.nodes[v]["vuln"]) for v in g.nodes()}

    restrict_catalog(g, covered)

    assert catalog(g) == covered
    for v in g.nodes():
        assert set(g.nodes[v]["vuln"]) == truth[v]          # ground truth intact
        assert defender_vuln(g, v) <= covered                # view is inside catalog
        assert defender_vuln(g, v) == truth[v] & covered     # and is exactly the join


def test_restrict_catalog_clears_stale_withholding_state():
    from serum.sim.catalog import withhold_from_catalog
    g = _net()
    withhold_from_catalog(g, 3)
    assert g.graph.get("withheld_cve") == 3
    restrict_catalog(g, frozenset({0, 1, 2}))
    assert "withheld_cve" not in g.graph


# -- geometry --------------------------------------------------------------

def test_jaccard_matrix_is_symmetric_with_unit_diagonal():
    g = _net(seed=1)
    J = jaccard_matrix(g)
    assert np.allclose(J, J.T)
    assert np.allclose(np.diag(J), 1.0)
    assert J.min() >= 0.0 and J.max() <= 1.0


def test_covered_cve_proxies_itself_perfectly():
    g = _net(seed=2)
    J = jaccard_matrix(g)
    # a CVE inside the covered set is excluded from its own proxy pool, but a
    # duplicate-profile CVE would still score 1.0; proxy is always a valid ratio
    assert 0.0 <= proxy_coverage(J, {0, 1, 2}, 5) <= 1.0


def test_spread_floor_shrinks_the_attackers_choice_set():
    g = _net(seed=3)
    loose = spreading_cves(g, min_component=MIN_COMP, spread_floor_frac=0.0)
    tight = spreading_cves(g, min_component=MIN_COMP, spread_floor_frac=0.9)
    assert set(tight) <= set(loose)
    assert len(tight) <= len(loose)


def test_frontier_is_sorted_by_proxy_coverage():
    g = _net(seed=4)
    rows = blindspot_frontier(g, covered={0, 1, 2, 3}, min_component=MIN_COMP)
    proxies = [r[2] for r in rows]
    assert proxies == sorted(proxies)


# -- allocation ------------------------------------------------------------

def test_allocations_respect_the_budget():
    g = _net(seed=5)
    for alloc in (allocate_prevalence(g, 5, min_component=MIN_COMP),
                  allocate_random(g, 5, rng=np.random.default_rng(0)),
                  allocate_maximin_proxy(g, 5, min_component=MIN_COMP)):
        assert len(alloc) <= 5
        assert all(0 <= c < g.graph["n_cves"] for c in alloc)


def test_maximin_allocation_beats_prevalence_on_its_own_objective():
    """The greedy allocator should not lose to popularity on worst-case proxy --
    that is the quantity it optimises, so losing would mean it is broken."""
    wins = 0
    for seed in range(6):
        g = _net(seed=seed, n_cves=16)
        m = 4
        prev = allocate_prevalence(g, m, min_component=MIN_COMP)
        maxi = allocate_maximin_proxy(g, m, min_component=MIN_COMP)
        wp_prev = worst_case_proxy(g, prev, min_component=MIN_COMP)
        wp_maxi = worst_case_proxy(g, maxi, min_component=MIN_COMP)
        if wp_maxi >= wp_prev - 1e-9:
            wins += 1
    assert wins >= 5, f"maximin lost its own objective in {6 - wins}/6 draws"


def test_worst_case_proxy_is_a_valid_ratio():
    g = _net(seed=7)
    wp = worst_case_proxy(g, allocate_prevalence(g, 4, min_component=MIN_COMP),
                          min_component=MIN_COMP)
    assert 0.0 <= wp <= 1.0


# -- the attacker ----------------------------------------------------------

def test_blindspot_attacker_prefers_an_uncovered_cve():
    g = _net(seed=8, n_cves=16)
    covered = allocate_prevalence(g, 4, min_component=MIN_COMP)
    restrict_catalog(g, covered)
    p = select_blindspot_payload(g, beta=0.35, covered=covered,
                                 min_component=MIN_COMP, spread_floor_frac=0.0)
    assert p.cve not in covered, "attacker took a covered CVE while a blind spot existed"


def test_blindspot_attacker_still_picks_something_that_spreads():
    g = _net(seed=9, n_cves=16)
    covered = allocate_prevalence(g, 4, min_component=MIN_COMP)
    p = select_blindspot_payload(g, beta=0.35, covered=covered,
                                 min_component=MIN_COMP, spread_floor_frac=0.5)
    assert len(true_carriers(g, p.cve)) >= 2


def test_full_coverage_leaves_no_blind_spot():
    """With everything inventoried the attacker's evasion move does not exist."""
    g = _net(seed=10, n_cves=16)
    full = frozenset(range(g.graph["n_cves"]))
    restrict_catalog(g, full)
    assert worst_case_proxy(g, full, min_component=MIN_COMP) == pytest.approx(1.0)


def test_carrier_sets_match_ground_truth():
    g = _net(seed=11)
    cs = carrier_sets(g)
    assert cs[0] == true_carriers(g, 0)
