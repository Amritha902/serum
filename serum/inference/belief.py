"""Bayesian belief over which CVE the worm is exploiting.

This is the inference that makes content-awareness *possible under partial
observation*. The defender never sees the payload. But spread is
vulnerability-gated: every host infected *by propagation* (i.e. not a planted
seed) must carry the target CVE. So each newly-infected non-seed host is a
hard likelihood constraint -- it zeroes the posterior mass on every CVE it is
not vulnerable to.

Formally, with a prior p0(c) over CVEs and the observed set I of
propagation-infected hosts,

    p(c | I) proportional to  p0(c) * prod_{v in I} 1[c in vuln(v)]

which, because the indicator is 0/1, collapses to the prior renormalised over
the set of CVEs consistent with *every* infected host. We additionally fold in
a soft prevalence prior (a widely deployed CVE is an a-priori more attractive
target) and expose a smoothed posterior so downstream planning degrades
gracefully while the support is still large.
"""

from __future__ import annotations

import numpy as np

from serum.sim.network import cve_prevalence


class CVEBelief:
    """Belief over the payload CVE with a *soft* likelihood.

    ``mode="soft"`` (default) models imperfect detection: an infected host is
    consistent with the true CVE with probability ``1-noise`` and, with
    probability ``noise``, may be a false positive (or a planted seed of unknown
    identity) that does not carry it. Each observation therefore *down-weights*
    rather than *eliminates* a CVE, so a single spurious report cannot wrongly
    exclude the truth -- the failure mode of the hard-consistency model. With
    ``noise=0`` (or ``mode="hard"``) it reduces to exact consistency filtering,
    which is what the identifiability theory analyses.
    """

    def __init__(self, g, prior: str = "prevalence", eps: float = 1e-6,
                 mode: str = "soft", noise: float = 0.03,
                 known_seeds: bool = True):
        self.g = g
        self.n_cves = g.graph["n_cves"]
        self.eps = eps
        self.mode = mode
        self.noise = float(noise)
        self.known_seeds = known_seeds
        if prior == "prevalence":
            base = cve_prevalence(g) + eps
        elif prior == "uniform":
            base = np.ones(self.n_cves)
        else:
            raise ValueError(f"unknown prior: {prior!r}")
        self.log_prior = np.log(base / base.sum())
        # hard-consistency flags (also used as an uncertainty proxy)
        self.consistent = np.ones(self.n_cves, dtype=bool)
        # accumulated soft log-likelihood
        self.log_lik = np.zeros(self.n_cves, dtype=float)
        self._log_hit = np.log(1.0 - self.noise + 1e-12)
        self._log_miss = np.log(self.noise + 1e-12)
        self._seen: set = set()

    def update(self, newly_infected, seeds) -> None:
        """Fold in one step of evidence (propagation-infected hosts)."""
        seeds = seeds if self.known_seeds else frozenset()
        for v in newly_infected:
            if v in seeds or v in self._seen:
                continue
            self._seen.add(v)
            vuln = self.g.nodes[v]["vuln"]
            for c in range(self.n_cves):
                carries = c in vuln
                if not carries:
                    self.consistent[c] = False
                if self.mode == "soft":
                    self.log_lik[c] += self._log_hit if carries else self._log_miss

    def posterior(self) -> np.ndarray:
        """Normalised posterior over CVEs given the evidence so far."""
        if self.mode == "hard":
            logp = self.log_prior.copy()
            if self.consistent.any():
                logp[~self.consistent] = -np.inf
        else:
            logp = self.log_prior + self.log_lik
        logp -= logp.max()
        p = np.exp(logp)
        s = p.sum()
        if s <= 0:  # degenerate; fall back to the surviving consistent set
            p = self.consistent.astype(float)
            s = p.sum() or 1.0
        return p / s

    def map_cve(self) -> int:
        """Most-probable CVE under the current posterior."""
        return int(self.posterior().argmax())

    def support_size(self) -> int:
        """Effective number of candidate CVEs -- a residual-uncertainty proxy.

        In hard mode this is the count still consistent; in soft mode it is the
        number carrying non-negligible posterior mass (so the agent's
        patch-vs-isolate switch degrades gracefully under noise)."""
        if self.mode == "hard":
            return int(self.consistent.sum())
        return int((self.posterior() > 0.02).sum())

    def entropy(self) -> float:
        p = self.posterior()
        nz = p[p > 0]
        return float(-(nz * np.log(nz)).sum())
