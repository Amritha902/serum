"""Detecting that your CVE catalog does not contain the thing spreading.

The problem. ``CVEBelief`` is a posterior over a *closed* catalog. If the real
exploit is outside that catalog (``serum.sim.catalog``), the posterior is not
merely diffuse -- it is confidently wrong, and it stays wrong no matter how much
evidence arrives, because the truth has no index to accumulate mass on. Worse,
the failure is silent: support size shrinks and entropy falls exactly as they do
in a healthy run, so every internal confidence signal the agent already has says
"I am learning" while it defends the wrong subgraph. A defender needs a separate
statistic that can say *my model class is wrong*, not *I am still unsure*.

The statistic. Vulnerability-gated spread gives us one for free. Let ``I`` be the
propagation-infected hosts observed so far (seeds excluded -- they were planted,
not exploited). Under a **well-specified catalog**, the true CVE ``c*`` is in the
catalog and *every* host in ``I`` genuinely carries it, so ``c*`` explains all of
``I`` except where the inventory failed to record it. Define

    cov(c) = |{v in I : c in vuln_observed(v)}|,
    unexplained = |I| - max_c cov(c).

Under H0 (well-specified, inventory miss rate m), ``|I| - cov(c*) ~ Bin(|I|, m)``,
and since ``max_c cov(c) >= cov(c*)`` we have ``unexplained <= |I| - cov(c*)``.
So ``unexplained`` is stochastically dominated by ``Bin(|I|, m)`` and the upper
tail

    p = P(Bin(|I|, m) >= unexplained)

is a **valid, conservative p-value** for H0 -- no multiplicity correction is
needed for the max over CVEs, because maximising can only shrink ``unexplained``
and therefore only inflate ``p``. That one-line argument is what makes this a
calibrated test rather than a tuned threshold.

Under H1 (the exploit is outside the catalog) no catalog CVE is causally tied to
who falls; the best-covering CVE only tracks ``I`` through co-occurrence, so
``unexplained`` grows linearly in ``|I|`` and ``p`` collapses.

Two consequences worth stating plainly:

  * With a **perfect inventory** (m -> 0) a single unexplainable infection is a
    *certificate* that the catalog is wrong -- the hard-consistency set going
    empty, restated as a hypothesis test. This is the honest version of the
    "empty consistent set" signal.
  * The **soft** likelihood mode that makes ``CVEBelief`` robust to detection
    noise is precisely what hides this signal from the posterior: soft updates
    never zero anything out, so the belief stays smooth while the model class is
    wrong. Robustness to noise and detectability of misspecification pull in
    opposite directions inside the belief, which is why the monitor has to live
    outside it.
"""

from __future__ import annotations

import numpy as np
from scipy import stats as ss

from serum.data.inventory import defender_vuln
from serum.sim.catalog import catalog


class MisspecificationMonitor:
    """Sequential, calibrated test that the payload is outside the catalog.

    Parameters
    ----------
    g : the network (read-only; the monitor uses the defender's observed view).
    alpha : significance level for the alarm. Because the p-value is
        conservative, the realised false-alarm rate on well-specified runs is
        at or below this.
    miss_floor : the inventory miss rate assumed under H0. Defaults to the
        graph's recorded ``inventory_miss``, floored at this value so that a
        nominally perfect inventory does not make the test infinitely touchy
        about a single anomalous host. Raising it buys robustness at the cost
        of detection latency.
    min_evidence : never alarm before this many propagation infections. Guards
        against alarming off one or two hosts early in an outbreak.
    """

    def __init__(self, g, alpha: float = 0.01, miss_floor: float = 0.02,
                 min_evidence: int = 4):
        self.g = g
        self.alpha = float(alpha)
        self.min_evidence = int(min_evidence)
        recorded = float(g.graph.get("inventory_miss", 0.0) or 0.0)
        self.miss_rate = max(float(miss_floor), recorded)
        self.cat = sorted(catalog(g))
        self._cov = {c: 0 for c in self.cat}
        self._n = 0                      # |I|: propagation infections folded in
        self._seen: set = set()
        self.alarm = False
        self.alarm_at: int | None = None   # |I| when the alarm first fired
        self.alarm_step: int | None = None  # env step when it first fired

    # -- evidence --------------------------------------------------------
    def update(self, newly_infected, seeds, t: int | None = None) -> None:
        """Fold in one step of propagation evidence, then re-test."""
        seeds = set(seeds or ())
        for v in newly_infected:
            if v in seeds or v in self._seen:
                continue
            self._seen.add(v)
            self._n += 1
            vuln = defender_vuln(self.g, v)
            for c in vuln:
                if c in self._cov:
                    self._cov[c] += 1
        if not self.alarm and self._n >= self.min_evidence and self.p_value() < self.alpha:
            self.alarm = True
            self.alarm_at = self._n
            self.alarm_step = t

    # -- the test --------------------------------------------------------
    def unexplained(self) -> int:
        """Infections no single catalog CVE can account for."""
        if self._n == 0:
            return 0
        best = max(self._cov.values()) if self._cov else 0
        return int(self._n - best)

    def p_value(self) -> float:
        """Conservative upper-tail p-value for H0 (catalog is well-specified)."""
        if self._n < 1:
            return 1.0
        k = self.unexplained()
        if k <= 0:
            return 1.0
        # P(Bin(n, m) >= k) == sf(k-1)
        return float(ss.binom.sf(k - 1, self._n, self.miss_rate))

    def evidence(self) -> int:
        """How many propagation infections have been folded in."""
        return self._n

    def explained_fraction(self) -> float:
        """Share of observed infections the best catalog CVE accounts for."""
        if self._n == 0:
            return 1.0
        return float(max(self._cov.values()) / self._n) if self._cov else 0.0
