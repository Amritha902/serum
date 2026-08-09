"""Containment that knows when to stop trusting its own vulnerability catalog.

``ContentAwareAgent`` is optimal-ish when the catalog contains the exploit and
pathological when it does not: it ranks frontier hosts by posterior mass on CVEs
those hosts carry, discards every host scoring zero, and returns an **empty
action list** when no frontier host carries a believed CVE. Against an
out-of-catalog zero-day that is the common case, so the strongest defender in
the suite degenerates into ``NoDefense`` precisely when the outbreak is one the
defender has never seen before.

``OpenWorldAgent`` closes that hole with two mechanisms, in increasing order of
how much evidence they need:

1. **Never idle** (needs no evidence). If the content-aware score selects fewer
   hosts than the budget allows, the remaining budget is spent on the best
   *structure-only* targets. Content-awareness should be a re-ranking of where
   to spend the budget, never a reason to leave it unspent. This alone removes
   the catastrophic tail without requiring any detection.

2. **Abandon the catalog on evidence** (needs ~a handful of infections). A
   ``MisspecificationMonitor`` runs alongside the belief. When it rejects the
   well-specified hypothesis at level ``alpha``, the agent stops weighting the
   posterior at all and defends as a payload-blind heuristic for the rest of the
   episode. The switch is latched: a catalog shown to be wrong does not become
   right again later, and latching keeps the policy from oscillating.

The fallback is ``GreedyBlockingDefense`` rather than ``DegreeDefense`` because
it is the strongest structure-only policy in the suite -- falling back to a weak
heuristic would flatter the method by making the fallback look costly.

What this buys, stated honestly: on **well-specified** outbreaks this agent
should be statistically indistinguishable from ``ContentAwareAgent`` (the
monitor's false-alarm rate is bounded by ``alpha``, and mechanism 1 rarely
binds). Its value is entirely in the open-world regime, and it is a *recovery*
result -- restoring structure-only parity when content-awareness would otherwise
collapse -- not a claim that it beats structure-only on exploits it cannot see.
"""

from __future__ import annotations

from serum.agents.content_aware import ContentAwareAgent
from serum.baselines.heuristics import GreedyBlockingDefense, frontier
from serum.inference.misspec import MisspecificationMonitor
from serum.sim.environment import Action


class OpenWorldAgent(ContentAwareAgent):
    """Content-aware containment with a latched catalog-misspecification switch."""

    name = "open-world"

    def __init__(self, g, alpha: float = 0.01, miss_floor: float = 0.02,
                 min_evidence: int = 4, never_idle: bool = True, **kw):
        super().__init__(g, **kw)
        self.monitor = MisspecificationMonitor(
            g, alpha=alpha, miss_floor=miss_floor, min_evidence=min_evidence
        )
        self.never_idle = bool(never_idle)
        self._fallback = GreedyBlockingDefense()

    # -- introspection used by the experiments ---------------------------
    @property
    def alarmed(self) -> bool:
        return self.monitor.alarm

    @property
    def alarm_at(self):
        """Number of propagation infections observed when the alarm fired."""
        return self.monitor.alarm_at

    def __call__(self, env, obs):
        if obs.t != self._last_t:
            self.monitor.update(obs.newly_infected, obs.seeds, t=obs.t)
            if self.update_belief:
                self.belief.update(obs.newly_infected, obs.seeds)
            self._last_t = obs.t

        # Latched: once the catalog is rejected, stay payload-blind.
        if self.monitor.alarm:
            return self._fallback(env, obs)

        front = frontier(env)
        if not front:
            return []

        posterior = self.belief.posterior()
        scored = [(self._exposed_vuln_degree(env, v, posterior), v) for v in front]
        chosen = [v for s, v in sorted(scored, reverse=True) if s > 0.0]

        k = min(env.budget_per_step, len(front))
        picks = chosen[:k]

        # Mechanism 1: spend leftover budget structurally rather than idling.
        if self.never_idle and len(picks) < k:
            taken = set(picks)
            rest = [v for v in front if v not in taken]
            rest.sort(key=lambda v: self._fallback._bridge_score(env, v), reverse=True)
            picks = picks + rest[: k - len(picks)]

        if not picks:
            return []

        # Patch only while the catalog is still credible and the belief narrow;
        # structural picks are never patch-able (no CVE to immunise against), so
        # they are always isolations.
        confident = self.belief.support_size() <= self.patch_threshold
        content_set = set(chosen[:k])
        return [
            Action.patch(v) if (confident and v in content_set) else Action.isolate(v)
            for v in picks
        ]
