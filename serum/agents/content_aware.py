"""The content-aware agent: containment that reasons about *what* is spreading.

Core idea. A payload targeting CVE c can only traverse the *vulnerable
subgraph* G_c induced by hosts that carry c. So the right quantity to defend
is not a host's degree in the physical topology, but its degree *inside the
propagation surface* -- how many still-susceptible, still-exploitable
neighbours it would infect next. The agent scores each frontier host by its
belief-weighted exposed-vulnerable degree and spends the budget top-down.

Under partial observation the agent does not know c. It maintains a
``CVEBelief`` and takes the expectation of the score over the posterior, so
early (high-uncertainty) decisions hedge across consistent CVEs and later
decisions sharpen as the outbreak reveals its target. When the posterior has
collapsed to a small support it also switches from isolation to *patching*
(availability-preserving) because it can now immunise precisely the hosts that
matter -- something a payload-blind defender can never justify.
"""

from __future__ import annotations

import numpy as np

from serum.baselines.heuristics import frontier
from serum.inference.belief import CVEBelief
from serum.sim.environment import Action, Status


class ContentAwareAgent:
    name = "content-aware"

    def __init__(self, g, prior: str = "prevalence", patch_when_support_leq: int = 3):
        self.belief = CVEBelief(g, prior=prior)
        self.patch_threshold = patch_when_support_leq
        self._last_t = -1

    def _exposed_vuln_degree(self, env, v, posterior) -> float:
        """Belief-weighted count of susceptible neighbours this host could
        infect: sum over CVEs c of P(c) * 1[v carries c] * (# susceptible
        neighbours that also carry c)."""
        g = env.g
        v_vuln = g.nodes[v]["vuln"]
        # Only CVEs that v itself carries can make v a spreader.
        cand = [c for c in v_vuln if posterior[c] > 0]
        if not cand:
            return 0.0
        score = 0.0
        for w in g.neighbors(v):
            if env.status[w] != Status.SUSCEPTIBLE or w in env.patched:
                continue
            w_vuln = g.nodes[w]["vuln"]
            for c in cand:
                if c in w_vuln:
                    score += posterior[c]
        return score

    def __call__(self, env, obs):
        # Update belief with the newest propagation evidence exactly once/step.
        if obs.t != self._last_t:
            self.belief.update(obs.newly_infected, obs.seeds)
            self._last_t = obs.t

        front = frontier(env)
        if not front:
            return []

        posterior = self.belief.posterior()
        scored = [(self._exposed_vuln_degree(env, v, posterior), v) for v in front]
        scored = [(s, v) for s, v in scored if s > 0.0]
        if not scored:
            return []
        scored.sort(reverse=True)

        k = min(env.budget_per_step, len(scored))
        confident = self.belief.support_size() <= self.patch_threshold
        actions = []
        for _, v in scored[:k]:
            # Once the CVE is nearly pinned down, patch (keep the host online);
            # while still uncertain, isolate (a blunt but certain cut).
            actions.append(Action.patch(v) if confident else Action.isolate(v))
        return actions


class OracleContentAware:
    """Upper bound: the same agent handed the true CVE (full observability).

    Not a real defender -- it measures how much performance the Bayesian
    inference leaves on the table."""

    name = "content-aware-oracle"

    def __init__(self, patch: bool = True):
        self.patch = patch

    def __call__(self, env, obs):
        cve = env.payload.cve  # oracle peek
        front = frontier(env)
        if not front:
            return []

        def exposed(v):
            if cve not in env.g.nodes[v]["vuln"]:
                return 0
            return sum(
                1
                for w in env.g.neighbors(v)
                if env.status[w] == Status.SUSCEPTIBLE
                and w not in env.patched
                and cve in env.g.nodes[w]["vuln"]
            )

        scored = [(exposed(v), v) for v in front]
        scored = [(s, v) for s, v in scored if s > 0]
        if not scored:
            return []
        scored.sort(reverse=True)
        k = min(env.budget_per_step, len(scored))
        make = Action.patch if self.patch else Action.isolate
        return [make(v) for _, v in scored[:k]]
