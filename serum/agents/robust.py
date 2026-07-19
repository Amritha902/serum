"""Poison-robust defender: audit the belief against the spread it predicts.

The committee result showed that averaging diverse beliefs does not defeat
belief-poisoning -- the beliefs fail together. But poisoning is a *one-time*
injection of decoys, whereas the real worm keeps spreading and keeps revealing
the true exploit. So a robust defender can **audit** its belief online: the
believed exploit predicts *which* hosts should fall next (those carrying it); if
actual new infections stop matching that prediction, the belief is unreliable
(poisoned or merely uncertain) and the agent **hedges** its budget toward
structure-only targets, which no belief attack can corrupt.

Concretely the agent maintains a trust weight `α ∈ [0,1]`, updated each
propagation step toward the fraction of new infections that carry the current
MAP CVE, and scores each frontier host as
    α · (content-aware score)  +  (1−α) · (structural score).
Under a clean outbreak `α → 1` (full content-awareness); under poisoning the
real spread contradicts the poisoned MAP, `α` falls, and the agent degrades
gracefully to structure-only instead of collapsing.
"""

from __future__ import annotations

import numpy as np

from serum.agents.content_aware import ContentAwareAgent
from serum.baselines.heuristics import frontier
from serum.data.inventory import defender_vuln
from serum.sim.environment import Action


class RobustAgent(ContentAwareAgent):
    name = "robust"

    def __init__(self, g, init_trust: float = 0.5, adapt: float = 0.3, **kw):
        super().__init__(g, **kw)
        self.trust = float(init_trust)
        self.adapt = float(adapt)

    def __call__(self, env, obs):
        if obs.t != self._last_t:
            # audit BEFORE folding in this step's evidence: do the latest
            # propagation infections match the believed exploit? (skip t=0, whose
            # "new infections" include planted seeds/decoys, not real spread).
            if obs.t > 0:
                map_cve = self.belief.map_cve()
                newly = [v for v in obs.newly_infected if v not in obs.seeds]
                if newly:
                    hit = sum(1 for v in newly
                              if map_cve in defender_vuln(env.g, v)) / len(newly)
                    self.trust = (1 - self.adapt) * self.trust + self.adapt * hit
            self.belief.update(obs.newly_infected, obs.seeds)
            self._last_t = obs.t

        front = frontier(env)
        if not front:
            return []
        post = self.belief.posterior()
        cs = np.array([self._exposed_vuln_degree(env, v, post) for v in front],
                      dtype=float)
        cs = cs / (cs.max() + 1e-9)
        ss = np.array([env.g.degree(v) for v in front], dtype=float)
        ss = ss / (ss.max() + 1e-9)
        score = self.trust * cs + (1.0 - self.trust) * ss

        order = np.argsort(score)[::-1]
        k = min(env.budget_per_step, len(front))
        # patch only when the belief is both narrow AND trusted; else isolate
        confident = self.belief.support_size() <= self.patch_threshold and self.trust > 0.5
        actions = []
        for i in order[:k]:
            if score[i] <= 0:
                break
            v = front[i]
            actions.append(Action.patch(v) if confident else Action.isolate(v))
        return actions
