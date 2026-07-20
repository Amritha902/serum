"""Tests for the optimal-stopping content-aware defender.

These exercise the two invariants the ``optimal_stopping.py`` experiment
depends on: (1) during the watch phase the agent applies *no* interventions
but *does* update the belief passively, (2) once triggered it delegates to
either the hedged content-aware agent or the MAP-commit act mode, and (3)
the adaptive trigger fires no later than a hard support threshold implies.
"""
from __future__ import annotations

import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from serum.agents.content_aware import ContentAwareAgent
from serum.agents.stopping import AdaptiveStopAgent, FixedStopAgent
from serum.baselines.heuristics import NoDefense
from serum.sim.environment import ContainmentEnv
from serum.sim.network import generate_network
from serum.sim.payload import sample_payload


def _make_env(seed=0, budget=5, horizon=30):
    rng = np.random.default_rng(seed)
    g = generate_network(n=200, n_cves=12, vuln_lambda=6.0,
                         popularity_alpha=0.8, rng=rng)
    pl = sample_payload(g, beta=0.35, strategy="band", rng=rng, band=(0.15, 0.6))
    carriers = [v for v, d in g.nodes(data=True) if pl.cve in d["vuln"]]
    seeds = [int(s) for s in rng.choice(carriers, size=3, replace=False)]
    return ContainmentEnv(g, pl, seeds, budget_per_step=budget, horizon=horizon,
                          rng=np.random.default_rng(seed + 1)), pl


def test_fixed_stop_watch_phase_takes_no_actions():
    """Before ``stop_time`` the fixed-stop agent must return no actions, so
    nothing gets isolated or patched during the watch phase."""
    env, _ = _make_env()
    ag = FixedStopAgent(env.g, stop_time=3)
    obs = env.reset()
    for _ in range(3):                     # steps 0, 1, 2 -- pure watch
        actions = ag(env, obs)
        assert actions == []
        if env.done():
            break
        obs = env.step(actions)
    assert not env.isolated and not env.patched
    # once t >= stop_time the agent starts producing actions (if a frontier exists)
    from serum.baselines.heuristics import frontier
    if frontier(env):
        actions = ag(env, obs)
        assert isinstance(actions, list)


def test_fixed_stop_t0_matches_content_aware_endstate():
    """FixedStopAgent(T=0) must behave identically to the plain
    ContentAwareAgent (paired outbreak, same RNG) -- the "act every step"
    baseline that anchors the wait-vs-spread curve at T=0."""
    env_a, _ = _make_env(seed=5)
    env_b, _ = _make_env(seed=5)
    r_ca = env_a.run(ContentAwareAgent(env_a.g))
    r_stop = env_b.run(FixedStopAgent(env_b.g, stop_time=0))
    assert r_ca.infected_fraction == pytest.approx(r_stop.infected_fraction)
    assert set(env_a.isolated) == set(env_b.isolated)


def test_belief_updates_passively_during_watch():
    """During the watch phase we still fold observations into the belief; by
    the time we would act, ``support_size()`` must have shrunk from the
    universe (unless no propagation ever occurred)."""
    env, _ = _make_env(seed=7)
    ag = FixedStopAgent(env.g, stop_time=100)  # never acts
    n_cves = env.g.graph["n_cves"]
    initial_support = ag.inner.belief.support_size()
    obs = env.reset()
    for _ in range(env.horizon):
        ag(env, obs)
        if env.done():
            break
        obs = env.step([])
    # Even without acting, evidence should have narrowed the support
    # (unless the outbreak died in the seed set, in which case there was
    # nothing to observe -- so we allow no-op only under that condition).
    if len(env._ever) > len(env.seeds):
        assert ag.inner.belief.support_size() < initial_support


def test_adaptive_stop_fires_when_support_shrinks():
    """A support-based adaptive stopper must trigger no later than the step
    at which the true support drops to the threshold. If it never triggers,
    that means the true support never got that small (a legitimate case)."""
    env, _ = _make_env(seed=11, budget=0)  # budget=0: pure passive observation
    ag = AdaptiveStopAgent(env.g, support_leq=3, min_watch=0)
    obs = env.reset()
    for _ in range(env.horizon):
        ag(env, obs)
        if env.done():
            break
        obs = env.step([])
    if ag.stop_at is not None:
        # At the trigger step the support must have been <= 3.
        assert ag.inner.belief.support_size() <= 3
    else:
        # Never triggered => the belief never converged that tight. Confirm:
        assert ag.inner.belief.support_size() > 3


def test_commit_mode_uses_map_cve_only():
    """Commit-mode patches only frontier hosts vulnerable to the MAP CVE --
    never a host that lacks it. This is the property that makes commit
    strictly more brittle than hedge to a wrong MAP."""
    env, pl = _make_env(seed=13)
    obs = env.reset()
    # Advance a few steps to build up the belief
    for _ in range(4):
        if env.done():
            break
        obs = env.step([])
    ag = FixedStopAgent(env.g, stop_time=0, act_mode="commit")
    # Prime the belief with what has happened so far
    ag.inner.belief.update(obs.newly_infected, obs.seeds)
    ag.inner._last_t = obs.t
    ag._stopped = True    # skip the internal trigger check
    actions = ag(env, obs)
    map_cve = int(ag.inner.belief.map_cve())
    for a in actions:
        assert a.kind == "patch"
        assert map_cve in env.g.nodes[a.target]["vuln"], \
            "commit-mode patched a host that does not carry the MAP CVE"


def test_optimal_stopping_time_is_zero_when_budget_is_perishable():
    """Paired sanity: on the SERUM defender with per-step (perishable) budget,
    delaying is monotonically worse than acting immediately. The T=0 policy
    must dominate T=8 in mean infected fraction across a handful of seeds --
    the negative result the experiment in scripts/optimal_stopping.py reports
    at scale.
    """
    inf_at_0, inf_at_8, inf_none = [], [], []
    for s in range(6):
        for target, delay in ((inf_at_0, 0), (inf_at_8, 8)):
            env, _ = _make_env(seed=s)
            target.append(env.run(FixedStopAgent(env.g, stop_time=delay)).infected_fraction)
        env, _ = _make_env(seed=s)
        inf_none.append(env.run(NoDefense()).infected_fraction)
    assert np.mean(inf_at_0) < np.mean(inf_at_8), \
        "T=0 should beat T=8 when budget is perishable per-step"
    assert np.mean(inf_at_0) < np.mean(inf_none), \
        "content-aware acting should beat no defense"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
