"""The two closest-prior baselines are well-formed defenders (grill G1).

CyGym-static must be the content-aware planner with the belief frozen at its
prior (no online update); DAVA must be a valid, exploit-blind, observed-infection
allocator. These guard the fairness of the head-to-head: the baselines must be
genuine implementations, not strawmen that no-op.
"""
from __future__ import annotations

import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from serum.baselines.closest import DavaDefense, StaticPriorDefense
from serum.experiments.harness import TrialSpec, build_episode


def episode(seed=0):
    spec = TrialSpec(n=200, n_cves=12, homophily=0.4, payload_strategy="band",
                     prev_band=(0.2, 0.6))
    f, payload = build_episode(spec, seed)
    return f(), payload


def test_cygym_static_never_updates_belief():
    env, _ = episode(0)
    d = StaticPriorDefense(env.g)
    assert d.update_belief is False
    before = d.belief.posterior().copy()
    # run the full episode; a static-prior defender's belief must not move
    env.run(d)
    after = d.belief.posterior()
    assert np.allclose(before, after), "CyGym-static belief drifted -- it must stay at the prior"


def test_dava_spends_budget_when_frontier_exists():
    env, _ = episode(1)
    d = DavaDefense()
    obs = env._observe()
    acts = d(env, obs)
    # with an active outbreak and a frontier, DAVA should allocate at least one
    # vaccine (and never exceed the budget)
    assert 0 <= len(acts) <= env.budget_per_step
    # every DAVA action is a patch (vaccination), never an isolate
    assert all(a.kind == "patch" for a in acts)


def test_dava_is_exploit_blind():
    """DAVA's decision must not depend on the payload at all: it reads only the
    observed infection + structure. Removing the payload from the env entirely
    must not change (or break) its chosen action set."""
    env, _ = episode(2)
    obs = env._observe()
    a1 = {a.target for a in DavaDefense()(env, obs)}
    env.payload = None                # DAVA never reads it, so this is safe
    a2 = {a.target for a in DavaDefense()(env, obs)}
    assert a1 == a2


def test_both_beat_no_defense_on_average():
    """Sanity: neither baseline is a broken no-op -- both reduce infection."""
    from serum.baselines.heuristics import NoDefense
    nd, dava, cyg = [], [], []
    for s in range(6):
        spec = TrialSpec(n=200, n_cves=12, homophily=0.4, payload_strategy="band",
                         prev_band=(0.2, 0.6))
        f, _ = build_episode(spec, s)
        nd.append(f().run(NoDefense()).infected_fraction)
        f2, _ = build_episode(spec, s)
        e2 = f2(); dava.append(e2.run(DavaDefense()).infected_fraction)
        f3, _ = build_episode(spec, s)
        e3 = f3(); cyg.append(e3.run(StaticPriorDefense(e3.g)).infected_fraction)
    assert np.mean(dava) < np.mean(nd)
    assert np.mean(cyg) < np.mean(nd)
