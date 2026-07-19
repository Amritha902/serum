"""Active-sensing agent (novelty N7): honeypot value-of-information probing.

The content-aware agent identifies the exploit passively, from who falls. When
the payload is non-identifiable (many confusers) that can be slow. An active
defender can instead *provoke* the information: deploy honeypots that emulate the
vulnerable service, get attacked, and capture the payload -- collapsing the
belief to the true CVE at once. This is dual control -- spend some budget to
*learn* (probe) and the rest to *act* (contain) -- and a value-of-information
placement: put honeypots where an attack is most imminent so a capture happens
fast. Once captured, the agent defends the exact vulnerable subgraph, like the
oracle.
"""

from __future__ import annotations

from serum.agents.content_aware import ContentAwareAgent
from serum.baselines.heuristics import frontier
from serum.sim.environment import Action, Status


class ProbingAgent(ContentAwareAgent):
    name = "content-aware+probe"

    def __init__(self, g, probe_fraction: float = 0.2,
                 probe_until_support: int = 3, **kw):
        super().__init__(g, **kw)
        self.probe_fraction = probe_fraction
        self.probe_until_support = probe_until_support

    def _infected_neighbours(self, env, v):
        return sum(1 for w in env.g.neighbors(v)
                   if env.status[w] == Status.INFECTED and w not in env.isolated)

    def _exposed_true(self, env, v, cve):
        if cve not in env.g.nodes[v]["vuln"]:
            return 0
        return sum(1 for w in env.g.neighbors(v)
                   if env.status[w] == Status.SUSCEPTIBLE and w not in env.patched
                   and cve in env.g.nodes[w]["vuln"])

    def __call__(self, env, obs):
        if obs.t != self._last_t:
            self.belief.update(obs.newly_infected, obs.seeds)
            self._last_t = obs.t

        front = frontier(env)
        if not front:
            return []
        budget = env.budget_per_step
        captured = obs.captured_cve is not None
        actions = []

        # --- explore: deploy honeypots while the exploit is still ambiguous ---
        if not captured and self.belief.support_size() > self.probe_until_support:
            n_probe = min(budget, max(1, round(self.probe_fraction * budget)))
            # value of information: a capture happens where an attack is imminent,
            # so probe the frontier hosts with the most infected neighbours.
            for v in sorted(front, key=lambda v: self._infected_neighbours(env, v),
                            reverse=True):
                if v in env.honeypots or self._infected_neighbours(env, v) == 0:
                    continue
                actions.append(Action.probe(v))
                if len(actions) >= n_probe:
                    break
            budget -= len(actions)

        # --- exploit: spend the rest on content-aware containment ---
        if captured:
            cve = obs.captured_cve
            scored = sorted(((self._exposed_true(env, v, cve), v) for v in front),
                            reverse=True)
            actions += [Action.patch(v) for s, v in scored if s > 0][:budget]
        else:
            posterior = self.belief.posterior()
            scored = sorted(((self._exposed_vuln_degree(env, v, posterior), v)
                             for v in front), reverse=True)
            confident = self.belief.support_size() <= self.patch_threshold
            for s, v in scored[:budget]:
                if s <= 0:
                    break
                actions.append(Action.patch(v) if confident else Action.isolate(v))
        return actions
