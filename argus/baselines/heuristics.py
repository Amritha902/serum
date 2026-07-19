"""Reactive containment policies that see topology but not the payload.

All policies here defend the *frontier* -- the susceptible hosts one hop from
the infected set -- because that is where the next round of infections comes
from. They differ only in how they *rank* frontier hosts for the limited
budget. None of them knows which CVE is spreading; that ignorance is exactly
what the content-aware agent removes.
"""

from __future__ import annotations

import networkx as nx
import numpy as np

from argus.sim.environment import Action, Status


def frontier(env) -> list:
    """Susceptible hosts adjacent to the current infected set."""
    front = set()
    for u in env._infected:
        if u in env.isolated:
            continue
        for v in env.g.neighbors(u):
            if env.status[v] == Status.SUSCEPTIBLE and v not in env.patched:
                front.add(v)
    return list(front)


class NoDefense:
    """Lower bound: let the worm burn."""

    name = "no-defense"

    def __call__(self, env, obs):
        return []


class RandomDefense:
    """Spend budget isolating random frontier hosts."""

    name = "random"

    def __init__(self, rng: np.random.Generator | None = None):
        self.rng = rng or np.random.default_rng()

    def __call__(self, env, obs):
        front = frontier(env)
        if not front:
            return []
        k = min(env.budget_per_step, len(front))
        chosen = self.rng.choice(len(front), size=k, replace=False)
        return [Action.isolate(front[i]) for i in chosen]


class DegreeDefense:
    """Isolate the highest total-degree frontier hosts (classic heuristic).

    This is the canonical structure-only strawman-that-isn't: degree
    immunisation is genuinely strong on homogeneous outbreaks. Its blind spot
    is that a high-degree host is irrelevant if it cannot carry the payload --
    budget spent on it is wasted."""

    name = "degree"

    def __call__(self, env, obs):
        front = frontier(env)
        if not front:
            return []
        front.sort(key=lambda v: env.g.degree(v), reverse=True)
        k = min(env.budget_per_step, len(front))
        return [Action.isolate(v) for v in front[:k]]


class BetweennessDefense:
    """Isolate frontier hosts on the most shortest-path bottlenecks.

    Betweenness is recomputed lazily and cached; on the outbreak's *residual*
    susceptible graph it identifies cut-like hosts. Still payload-blind."""

    name = "betweenness"

    def __init__(self):
        self._cache = None

    def __call__(self, env, obs):
        front = frontier(env)
        if not front:
            return []
        if self._cache is None:
            # betweenness on the physical topology (approximate, k-sampled for speed)
            k = min(env.n, 128)
            self._cache = nx.betweenness_centrality(
                env.g, k=k, seed=int(env.rng.integers(0, 2**31 - 1))
            )
        front.sort(key=lambda v: self._cache.get(v, 0.0), reverse=True)
        k = min(env.budget_per_step, len(front))
        return [Action.isolate(v) for v in front[:k]]
