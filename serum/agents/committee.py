"""Committee agent: a panel of belief-agents that debate and aggregate robustly.

A single exploit belief has one failure mode: a soft belief follows heavy
poisoning, a hard belief is brittle to a single decoy. A *committee* of agents
with **diverse** beliefs (soft at several noise levels, hard, uniform-prior)
each score the frontier under their own posterior, and the committee aggregates
by the **median** score per host. The median is robust to a minority of
mis-led members: an attacker who poisons the belief fools some members, but the
consensus of the rest still points at the right hosts. This is the agents
"talking to each other" -- proposing, then out-voting the outliers -- and it is
motivated directly by the deception result (a lone belief is overwhelmed by
heavy poisoning; a diverse quorum is not).
"""

from __future__ import annotations

import numpy as np

from serum.agents.content_aware import ContentAwareAgent
from serum.baselines.heuristics import frontier
from serum.sim.environment import Action

# A deliberately diverse panel: different robustness/priors so they fail
# independently under an attack.
DEFAULT_PANEL = [
    {"belief_mode": "soft", "belief_noise": 0.02},
    {"belief_mode": "soft", "belief_noise": 0.08},
    {"belief_mode": "soft", "belief_noise": 0.15},
    {"belief_mode": "hard"},
    {"prior": "uniform", "belief_mode": "soft", "belief_noise": 0.05},
]


class CommitteeAgent:
    name = "committee"

    def __init__(self, g, panel=None, aggregate: str = "median",
                 n_structural: int = 2, patch_when_support_leq: int = 3):
        cfgs = panel if panel is not None else DEFAULT_PANEL
        self.members = [ContentAwareAgent(g, **cfg) for cfg in cfgs]
        # structure-only voters (degree / eigenvector) are immune to belief
        # poisoning; they anchor the consensus when the belief members are fooled.
        self.n_structural = n_structural
        self.aggregate = aggregate
        self.patch_threshold = patch_when_support_leq
        self._eig = None

    def __call__(self, env, obs):
        front = frontier(env)
        if not front:
            return []

        rows = []
        supports = []
        for m in self.members:
            if obs.t != m._last_t:
                m.belief.update(obs.newly_infected, obs.seeds)
                m._last_t = obs.t
            post = m.belief.posterior()
            s = np.array([m._exposed_vuln_degree(env, v, post) for v in front],
                         dtype=float)
            s = s / (s.max() + 1e-9)          # per-member normalisation -> comparable votes
            rows.append(s)
            supports.append(m.belief.support_size())

        # structure-only voters (poison-immune): degree, and eigenvector if asked
        if self.n_structural >= 1:
            deg = np.array([env.g.degree(v) for v in front], dtype=float)
            rows.append(deg / (deg.max() + 1e-9))
        if self.n_structural >= 2:
            if self._eig is None:
                import networkx as nx
                try:
                    self._eig = nx.eigenvector_centrality_numpy(env.g)
                except Exception:
                    self._eig = dict(env.g.degree())
            ev = np.array([self._eig.get(v, 0.0) for v in front], dtype=float)
            rows.append(ev / (ev.max() + 1e-9))

        mat = np.vstack(rows)                  # (belief + structural) x frontier
        agg = np.median(mat, axis=0) if self.aggregate == "median" else mat.mean(axis=0)

        order = np.argsort(agg)[::-1]
        k = min(env.budget_per_step, len(front))
        confident = float(np.median(supports)) <= self.patch_threshold
        actions = []
        for i in order[:k]:
            if agg[i] <= 0:
                break
            v = front[i]
            actions.append(Action.patch(v) if confident else Action.isolate(v))
        return actions
