"""Optimal stopping for content-aware containment: watch, then act.

Every content-aware step spends its budget by taking the expectation of the
exposed-vulnerable-degree score over the current CVE posterior. When the
posterior is broad, the hedge blurs the score across many candidate CVEs and
the same budget dilutes across the wrong hosts; when it is narrow, the same
budget lands on precisely the hosts that matter. So there is a real trade-off:

    act early -> misspent budget under uncertainty
    act late  -> better belief but a larger frontier to contain

This module lets a defender *stop watching and start acting* on an explicit
trigger — either a fixed time horizon (an oracle-style baseline) or an adaptive
signal derived from the belief itself (posterior support shrinks, entropy drops,
top-mass rises, or a MAP CVE stabilises across consecutive steps). During the
watch phase the defender applies no interventions but keeps updating its belief
from every propagation infection it sees. Once the trigger fires it hands off
to a wrapped ``ContentAwareAgent`` for the rest of the episode.

Two policies live here:

  * ``FixedStopAgent(T)``: commit at step ``t == T``. Sweeping ``T`` traces
    the classic wait-vs-spread curve; its minimum is the *oracle* stopping
    time. A real defender does not know ``T``.
  * ``AdaptiveStopAgent(...)``: commit when the belief itself says so. The
    claim we test is that a belief-driven trigger matches (or beats) the
    oracle-best fixed ``T`` *without* knowing which outbreak it faces.
"""

from __future__ import annotations

from serum.agents.content_aware import ContentAwareAgent
from serum.baselines.heuristics import frontier
from serum.sim.environment import Action, Status


class _StopBase:
    """Shared machinery: run a passive belief update every step, and once a
    subclass flips ``self._stopped`` to True, delegate the rest of the episode
    to the configured act policy.

    Two act modes are supported:

    * ``act_mode="hedge"`` (default): delegate to a wrapped
      ``ContentAwareAgent`` that hedges its score over the full posterior.
      Under this well-designed defender, waiting is *not* rewarded because
      early hedging already handles CVE uncertainty — you'll typically find
      the optimal stopping time is ``T=0``.
    * ``act_mode="commit"``: patch only hosts vulnerable to the *MAP* CVE
      (a single committed guess, no hedging). This exposes the classical
      Wald-style sequential-testing trade-off: committing too early on a
      wrong MAP is expensive; waiting improves the MAP but leaks spread.
    """

    def __init__(self, g, *, act_mode: str = "hedge", **inner_kwargs):
        self.act_mode = act_mode
        self.inner = ContentAwareAgent(g, **inner_kwargs)
        self._stopped = False
        self.stop_at: int | None = None

    def _should_stop(self, env, obs) -> bool:
        raise NotImplementedError

    def _act_commit(self, env) -> list:
        """Patch the frontier hosts vulnerable to the current MAP CVE.

        This is the ``commit`` act mode: no hedging, full trust in the belief.
        When the MAP is right this is maximally efficient (every budget unit
        lands on an exploitable host); when wrong it wastes the whole step.
        """
        map_cve = int(self.inner.belief.map_cve())
        front = frontier(env)
        if not front:
            return []
        cand = [v for v in front if map_cve in env.g.nodes[v]["vuln"]]
        if not cand:
            return []

        def exposed(v):
            return sum(
                1 for w in env.g.neighbors(v)
                if env.status[w] == Status.SUSCEPTIBLE
                and w not in env.patched
                and map_cve in env.g.nodes[w]["vuln"]
            )

        cand.sort(key=exposed, reverse=True)
        k = min(env.budget_per_step, len(cand))
        return [Action.patch(v) for v in cand[:k]]

    def __call__(self, env, obs):
        # Belief always updates during the watch phase (once per step). We hold
        # inner._last_t forward too so the inner agent doesn't double-update
        # after we hand off.
        if obs.t != self.inner._last_t:
            self.inner.belief.update(obs.newly_infected, obs.seeds)
            self.inner._last_t = obs.t

        if not self._stopped and self._should_stop(env, obs):
            self._stopped = True
            self.stop_at = obs.t

        if not self._stopped:
            return []  # pure watch: no interventions
        if self.act_mode == "commit":
            return self._act_commit(env)
        return self.inner(env, obs)


class FixedStopAgent(_StopBase):
    """Commit at a fixed step ``T`` regardless of belief state.

    ``T=0`` collapses to the plain content-aware agent (act every step from
    the start); large ``T`` is the "watch forever" limit. Sweeping ``T`` is
    the fair baseline against which any adaptive rule must be measured.
    """

    def __init__(self, g, stop_time: int, **inner_kwargs):
        super().__init__(g, **inner_kwargs)
        self.stop_time = int(stop_time)

    @property
    def name(self) -> str:
        return f"fixed-stop-t{self.stop_time}"

    def _should_stop(self, env, obs) -> bool:
        return obs.t >= self.stop_time


class AdaptiveStopAgent(_StopBase):
    """Commit when the belief crosses a threshold.

    The four available triggers are combined by *first hit* (any one suffices):

    * ``support_leq``: hard-consistency support size ``|C_t|`` (# CVEs still
      consistent with every observed propagation infection).
    * ``entropy_leq``: Shannon entropy of the posterior, in nats.
    * ``top_mass_geq``: posterior probability on the MAP CVE.
    * ``map_stable_for``: number of consecutive steps the MAP CVE has been
      unchanged (a light "belief has settled" heuristic).

    A minimum-wait floor ``min_watch`` prevents the trivial degenerate case of
    triggering at ``t=0`` on the prior alone (the prior can be very peaked on
    real data even before any evidence has arrived).
    """

    def __init__(
        self,
        g,
        *,
        support_leq: int | None = 3,
        entropy_leq: float | None = None,
        top_mass_geq: float | None = None,
        map_stable_for: int | None = None,
        min_watch: int = 1,
        **inner_kwargs,
    ):
        super().__init__(g, **inner_kwargs)
        self.support_leq = support_leq
        self.entropy_leq = entropy_leq
        self.top_mass_geq = top_mass_geq
        self.map_stable_for = map_stable_for
        self.min_watch = int(min_watch)
        self._last_map: int | None = None
        self._map_streak: int = 0

    @property
    def name(self) -> str:
        parts = []
        if self.support_leq is not None:
            parts.append(f"S<={self.support_leq}")
        if self.entropy_leq is not None:
            parts.append(f"H<={self.entropy_leq:g}")
        if self.top_mass_geq is not None:
            parts.append(f"p*>={self.top_mass_geq:g}")
        if self.map_stable_for is not None:
            parts.append(f"map={self.map_stable_for}")
        tag = ",".join(parts) or "none"
        return f"adaptive-stop({tag})"

    def _should_stop(self, env, obs) -> bool:
        if obs.t < self.min_watch:
            return False
        belief = self.inner.belief
        if self.support_leq is not None and belief.support_size() <= self.support_leq:
            return True
        if self.entropy_leq is not None and belief.entropy() <= self.entropy_leq:
            return True
        if self.top_mass_geq is not None:
            p = belief.posterior()
            if float(p.max()) >= self.top_mass_geq:
                return True
        if self.map_stable_for is not None:
            m = belief.map_cve()
            if m == self._last_map:
                self._map_streak += 1
            else:
                self._map_streak = 1
                self._last_map = m
            if self._map_streak >= self.map_stable_for:
                return True
        return False
