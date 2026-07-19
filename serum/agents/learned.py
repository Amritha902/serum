"""Learned containment policy over belief-augmented features (novelty N9).

Vanilla GNN+RL immunization is established (RLGN, FINDER); the defensible version
here is *learning to contain under exploit uncertainty* -- a policy whose inputs
include the Bayesian belief over the payload, not just topology. We keep it
dependency-light (no PyTorch): a linear policy over per-host features scored and
trained by the cross-entropy method (`scripts/train_policy.py`). It can recover
and combine the hand-designed content-aware signal with structural cues, and the
belief features are what let it act correctly before the exploit is revealed.
"""

from __future__ import annotations

import numpy as np

from serum.agents.content_aware import ContentAwareAgent
from serum.baselines.heuristics import frontier
from serum.sim.environment import Action, Status

FEATURE_NAMES = [
    "exposed_vuln_degree",   # belief-weighted (the content-aware signal)
    "degree/10",             # structural centrality proxy
    "infected_neighbours",   # exposure
    "susceptible_neighbours",# onward reach
    "vuln_to_MAP_cve",       # carries the most-probable exploit
    "bias",
]
N_FEATURES = len(FEATURE_NAMES)


class LearnedPolicy(ContentAwareAgent):
    name = "learned"

    def __init__(self, g, weights=None, **kw):
        super().__init__(g, **kw)
        self.w = (np.asarray(weights, dtype=float) if weights is not None
                  else np.zeros(N_FEATURES))

    def _features(self, env, v, posterior, map_cve):
        evd = self._exposed_vuln_degree(env, v, posterior)
        deg = env.g.degree(v)
        inf_n = sum(1 for w in env.g.neighbors(v)
                    if env.status[w] == Status.INFECTED and w not in env.isolated)
        sus_n = sum(1 for w in env.g.neighbors(v)
                    if env.status[w] == Status.SUSCEPTIBLE and w not in env.patched)
        vmap = 1.0 if map_cve in env.g.nodes[v]["vuln"] else 0.0
        return np.array([evd, deg / 10.0, inf_n, sus_n, vmap, 1.0])

    def __call__(self, env, obs):
        if obs.t != self._last_t:
            self.belief.update(obs.newly_infected, obs.seeds)
            self._last_t = obs.t
        front = frontier(env)
        if not front:
            return []
        posterior = self.belief.posterior()
        map_cve = self.belief.map_cve()
        scored = sorted(((float(self.w @ self._features(env, v, posterior, map_cve)), v)
                         for v in front), reverse=True)
        k = min(env.budget_per_step, len(scored))
        confident = self.belief.support_size() <= self.patch_threshold
        actions = []
        for s, v in scored[:k]:
            actions.append(Action.patch(v) if confident else Action.isolate(v))
        return actions
