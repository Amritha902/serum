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

from serum.sim.environment import Action, Status


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


class EigenvectorDefense:
    """Isolate frontier hosts with the highest eigenvector centrality.

    Eigenvector centrality rewards hosts connected to other well-connected
    hosts -- a strong spectral notion of influence. Still payload-blind: it
    scores the physical topology, not the exploitable one."""

    name = "eigenvector"

    def __init__(self):
        self._cache = None

    def __call__(self, env, obs):
        front = frontier(env)
        if not front:
            return []
        if self._cache is None:
            try:
                self._cache = nx.eigenvector_centrality_numpy(env.g)
            except Exception:
                self._cache = nx.degree_centrality(env.g)  # fallback
        front.sort(key=lambda v: self._cache.get(v, 0.0), reverse=True)
        k = min(env.budget_per_step, len(front))
        return [Action.isolate(v) for v in front[:k]]


class GreedyBlockingDefense:
    """Greedy influence-blocking: isolate the frontier host whose removal cuts
    the most *susceptible* reachable mass right now.

    This is the standard strong heuristic for influence minimisation. It is
    myopically optimal against structure -- but it still counts *all* reachable
    susceptibles, not just the exploitable ones, so it over-values hubs the
    payload cannot use. Greedy is recomputed each step over the frontier only,
    keeping it tractable."""

    name = "greedy-blocking"

    def _susceptible_reach(self, env, v):
        # size of the susceptible component reachable from v if v stays online
        seen = {v}
        stack = [v]
        while stack:
            u = stack.pop()
            for w in env.g.neighbors(u):
                if w in seen or w in env.isolated or w in env.patched:
                    continue
                if env.status[w] == Status.SUSCEPTIBLE:
                    seen.add(w)
                    stack.append(w)
        return len(seen)

    def __call__(self, env, obs):
        front = frontier(env)
        if not front:
            return []
        # score by reachable susceptible mass; isolate the top-budget cut hosts
        front.sort(key=lambda v: self._susceptible_reach(env, v), reverse=True)
        k = min(env.budget_per_step, len(front))
        return [Action.isolate(v) for v in front[:k]]


class AcquaintanceDefense:
    """Acquaintance immunization (Cohen et al. 2003): isolate a *random
    neighbour* of a random infected host.

    Exploits the friendship paradox -- a random neighbour is a high-degree host
    in expectation -- to target hubs without computing centrality. A famously
    strong, cheap, *local* structure-only baseline. Payload-blind."""

    name = "acquaintance"

    def __init__(self, rng: np.random.Generator | None = None):
        self.rng = rng or np.random.default_rng()

    def __call__(self, env, obs):
        front = set(frontier(env))
        if not front:
            return []
        actions, tries = [], 0
        chosen = set()
        infected = list(env._infected)
        while len(actions) < env.budget_per_step and tries < 20 * env.budget_per_step:
            tries += 1
            if not infected:
                break
            u = infected[int(self.rng.integers(len(infected)))]
            nbrs = [w for w in env.g.neighbors(u) if w in front and w not in chosen]
            if not nbrs:
                continue
            v = nbrs[int(self.rng.integers(len(nbrs)))]
            chosen.add(v)
            actions.append(Action.isolate(v))
        return actions
