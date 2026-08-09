"""Open-world containment: catalog withholding, the misspecification monitor,
and the agent that latches onto its alarm."""
from __future__ import annotations

import numpy as np
import pytest

from serum.agents.content_aware import ContentAwareAgent
from serum.agents.openworld import OpenWorldAgent
from serum.baselines.heuristics import GreedyBlockingDefense
from serum.data.inventory import defender_vuln
from serum.inference.misspec import MisspecificationMonitor
from serum.sim.catalog import (
    catalog,
    is_open_world,
    proxy_overlap,
    true_carriers,
    withhold_confusable,
    withhold_from_catalog,
)
from serum.sim.environment import ContainmentEnv
from serum.sim.network import generate_network
from serum.sim.payload import Payload


def _net(seed=0, n=200, n_cves=12):
    return generate_network(n=n, topology="ba", m=3, n_cves=n_cves,
                            vuln_lambda=6.0, popularity_alpha=0.8,
                            rng=np.random.default_rng(seed))


# -- catalog ---------------------------------------------------------------

def test_withholding_hides_cve_from_defender_but_not_from_truth():
    g = _net()
    c = 3
    carriers_before = true_carriers(g, c)
    assert carriers_before, "need a CVE with carriers for this test to mean anything"

    withhold_from_catalog(g, c)

    # ground truth untouched -> spread dynamics are unaffected
    assert true_carriers(g, c) == carriers_before
    # defender cannot see it anywhere
    assert all(c not in defender_vuln(g, v) for v in g.nodes())
    assert c not in catalog(g)
    assert is_open_world(g)


def test_withholding_leaves_other_cves_intact():
    g = _net()
    other = 5
    before = {v: (other in defender_vuln(g, v)) for v in g.nodes()}
    withhold_from_catalog(g, 3)
    after = {v: (other in defender_vuln(g, v)) for v in g.nodes()}
    assert before == after


def test_withhold_confusable_strips_proxies_and_lowers_residual():
    g = _net(seed=1, n_cves=16)
    c = int(np.argmax([len(true_carriers(g, k)) for k in range(g.graph["n_cves"])]))

    g0 = _net(seed=1, n_cves=16)
    _, residual_j0 = withhold_confusable(g0, c, j=0)
    g4 = _net(seed=1, n_cves=16)
    withheld4, residual_j4 = withhold_confusable(g4, c, j=4)

    assert len(withheld4) == 5                      # the CVE plus its 4 proxies
    assert residual_j4 <= residual_j0 + 1e-12       # stripping proxies can only hurt
    assert 0.0 <= residual_j4 <= 1.0


def test_proxy_overlap_needs_no_ground_truth_about_the_catalog():
    """The audit statistic is computable from the inventory the defender has."""
    g = _net(seed=2)
    best, j = proxy_overlap(g, 0)
    assert best is not None and best != 0
    assert 0.0 <= j <= 1.0


# -- the monitor -----------------------------------------------------------

def test_monitor_stays_quiet_when_catalog_is_well_specified():
    """Every infected host really carries the true CVE, so nothing is unexplained."""
    g = _net(seed=3)
    c = 2
    infected = list(true_carriers(g, c))[:12]
    assert len(infected) >= 5

    m = MisspecificationMonitor(g, alpha=0.01, miss_floor=0.02, min_evidence=4)
    m.update(infected, seeds=frozenset(), t=1)
    assert m.unexplained() == 0
    assert m.p_value() == 1.0
    assert not m.alarm


def test_monitor_fires_when_the_true_cve_is_withheld():
    g = _net(seed=4, n_cves=16)
    # pick a CVE whose carriers are not all explained by one other CVE
    c = 1
    infected = list(true_carriers(g, c))[:25]
    if len(infected) < 10:
        pytest.skip("not enough carriers in this draw")
    withhold_confusable(g, c, j=6)   # remove it and its closest proxies

    m = MisspecificationMonitor(g, alpha=0.01, miss_floor=0.02, min_evidence=4)
    m.update(infected, seeds=frozenset(), t=1)
    assert m.unexplained() > 0
    assert m.alarm
    assert m.alarm_at is not None and m.alarm_at >= 4


def test_monitor_never_alarms_below_min_evidence():
    g = _net(seed=5, n_cves=16)
    c = 1
    infected = list(true_carriers(g, c))[:3]
    withhold_confusable(g, c, j=6)
    m = MisspecificationMonitor(g, alpha=0.01, min_evidence=4)
    m.update(infected, seeds=frozenset(), t=1)
    assert not m.alarm


def test_seeds_are_excluded_from_evidence():
    """Planted patient-zeros were not exploited, so they carry no information."""
    g = _net(seed=6)
    c = 2
    carriers = list(true_carriers(g, c))[:10]
    m = MisspecificationMonitor(g, min_evidence=1)
    m.update(carriers, seeds=frozenset(carriers), t=1)
    assert m.evidence() == 0


# -- the agent -------------------------------------------------------------

def _episode(g, cve, seed=0):
    carriers = sorted(true_carriers(g, cve))
    seeds = carriers[:3]
    return ContainmentEnv(g=g, payload=Payload(cve=cve, beta=0.35), seeds=seeds,
                          budget_per_step=5, horizon=20,
                          rng=np.random.default_rng(seed))


def test_open_world_agent_matches_content_aware_when_catalog_is_right():
    """Open-world safety should be ~free on well-specified outbreaks."""
    g = _net(seed=7)
    c = 2
    a = _episode(g, c, seed=11).run(ContentAwareAgent(g))
    b = _episode(g, c, seed=11).run(OpenWorldAgent(g))
    assert b.infected_fraction == pytest.approx(a.infected_fraction, abs=0.02)


def test_open_world_agent_never_leaves_budget_idle():
    """The catastrophic tail: content-aware can return no actions at all when no
    frontier host carries a believed CVE. The open-world agent must not."""
    g = _net(seed=8, n_cves=16)
    c = 1
    if len(true_carriers(g, c)) < 10:
        pytest.skip("not enough carriers in this draw")
    withhold_confusable(g, c, j=8)

    env = _episode(g, c, seed=12)
    obs = env.reset()
    env.step([])                      # let the worm move once so a frontier exists
    obs = env._observe()

    agent = OpenWorldAgent(g)
    acted = False
    for _ in range(6):
        actions = agent(env, obs)
        if actions:
            acted = True
            break
        obs = env.step(actions or [])
    assert acted, "open-world agent sat idle through an outbreak"


def test_alarm_latches_and_falls_back_to_structure():
    g = _net(seed=9, n_cves=16)
    c = 1
    if len(true_carriers(g, c)) < 10:
        pytest.skip("not enough carriers in this draw")
    withhold_confusable(g, c, j=8)

    agent = OpenWorldAgent(g, min_evidence=1)
    env = _episode(g, c, seed=13)
    obs = env.reset()
    for _ in range(10):
        obs = env.step(agent(env, obs))
    if agent.alarmed:
        # once alarmed it must behave exactly like the structural fallback
        assert isinstance(agent._fallback, GreedyBlockingDefense)
        before = agent.monitor.alarm_at
        obs = env.step(agent(env, obs))
        assert agent.alarmed and agent.monitor.alarm_at == before
