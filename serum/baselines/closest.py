"""The two closest prior systems, as runnable baselines (mitigates grill G1).

The review's sharpest attack: SERUM names CyGym (2025) as "the nearest system"
and DAVA (Zhang & Prakash 2015) as "the nearest data-aware method," yet neither
was ever run -- every beaten baseline was a 2002-2016 structure-only heuristic.
This module implements both so the head-to-head is an *experiment*, not prose.

Honest scope of these reimplementations:
  * We reproduce each system's *epistemic stance on our substrate*, not its full
    original machinery. The axis under test is what SERUM actually claims to
    improve: how the defender reasons about the unobserved exploit.
  * CyGym-static: a *static, common-knowledge prior* over exploits with *no
    online belief update* (CyGym computes an offline equilibrium policy that is
    independent of the realised zero-day). On our substrate that is exactly the
    content-aware planner with the belief frozen at its prior. We do NOT
    reimplement CyGym's PSRO game; we isolate the static-prior-vs-online-inference
    axis, which is the claimed gap.
  * DAVA: *data-aware* allocation that conditions on the OBSERVED-INFECTED
    subgraph but is *exploit-blind*. We use a per-step greedy shield-value proxy
    for DAVA's dominator-tree allocation. This is the sharpest "data-aware vs
    content-aware" contrast: DAVA conditions on the infection *state*; SERUM
    conditions on the inferred *exploit* and its vulnerable subgraph.
"""

from __future__ import annotations

from serum.agents.content_aware import ContentAwareAgent
from serum.baselines.heuristics import frontier
from serum.sim.environment import Action, Status


class StaticPriorDefense(ContentAwareAgent):
    """CyGym-style defender: static common-knowledge exploit prior, NO online
    belief update. Identical planner to the content-aware agent, but the belief
    never folds in the observed spread -- so it defends the *prior-expected*
    vulnerable surface rather than the *inferred* one. The gap between this and
    the content-aware agent is exactly what online inference buys."""

    name = "cygym-static"

    def __init__(self, g, **kw):
        kw["update_belief"] = False
        super().__init__(g, **kw)


class DavaDefense:
    """DAVA-style data-aware vaccine allocation (Zhang & Prakash 2015), exploit-blind.

    Conditions on the observed-infected subgraph -- vaccinates the hosts that
    shield the most susceptible mass from the current infection -- but never
    reasons about *which* vulnerability is spreading. Per-step greedy shield
    value: exposure to the observed infected set times onward spreading degree.
    Vaccination = patch (availability-preserving, needs no CVE), which is the
    faithful DAVA action and is generous (no availability cost)."""

    name = "dava"

    def __call__(self, env, obs):
        front = frontier(env)
        if not front:
            return []
        src = getattr(env, "_observed_infected", None)
        if src is None:
            src = env._infected

        def shield(v):
            exposure = sum(1 for w in env.g.neighbors(v)
                           if w in src and w not in env.isolated)
            if exposure == 0:
                return 0
            onward = sum(1 for w in env.g.neighbors(v)
                         if env.status[w] == Status.SUSCEPTIBLE and w not in env.patched)
            return exposure * (1 + onward)

        scored = [(shield(v), v) for v in front]
        scored = [(s, v) for s, v in scored if s > 0]
        if not scored:
            return []
        scored.sort(reverse=True)
        k = min(env.budget_per_step, len(scored))
        return [Action.patch(v) for _, v in scored[:k]]
