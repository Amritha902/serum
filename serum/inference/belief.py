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
    def __init__(self, g, prior: str = "prevalence", eps: float = 1e-6):
        self.g = g
        self.n_cves = g.graph["n_cves"]
        self.eps = eps
        if prior == "prevalence":
            base = cve_prevalence(g) + eps
        elif prior == "uniform":
            base = np.ones(self.n_cves)
        else:
            raise ValueError(f"unknown prior: {prior!r}")
        self.log_prior = np.log(base / base.sum())
        # consistency[c] == True while CVE c remains compatible with all evidence
        self.consistent = np.ones(self.n_cves, dtype=bool)
        self._seen: set = set()

    def update(self, newly_infected, seeds) -> None:
        """Fold in one step of evidence (propagation-infected hosts only)."""
        for v in newly_infected:
            if v in seeds or v in self._seen:
                continue
            self._seen.add(v)
            vuln = self.g.nodes[v]["vuln"]
            for c in range(self.n_cves):
                if self.consistent[c] and c not in vuln:
                    self.consistent[c] = False

    def posterior(self) -> np.ndarray:
        """Normalised posterior over CVEs given the evidence so far."""
        logp = self.log_prior.copy()
        if self.consistent.any():
            logp[~self.consistent] = -np.inf
        logp -= logp.max()
        p = np.exp(logp)
        s = p.sum()
        if s <= 0:  # evidence contradicted the prior support; fall back to flat
            p = self.consistent.astype(float)
            s = p.sum() or 1.0
        return p / s

    def map_cve(self) -> int:
        """Most-probable CVE under the current posterior."""
        return int(self.posterior().argmax())

    def support_size(self) -> int:
        """How many CVEs remain consistent -- a proxy for residual uncertainty."""
        return int(self.consistent.sum())

    def entropy(self) -> float:
        p = self.posterior()
        nz = p[p > 0]
        return float(-(nz * np.log(nz)).sum())
