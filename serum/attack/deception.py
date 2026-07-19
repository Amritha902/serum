"""Belief-poisoning deception attacker (adversarial group testing).

Beyond choosing a hard-to-identify payload (see adversarial.py), an attacker can
attack the defender's inference directly by *planting decoy infections*: hosts it
compromises through a side channel (phishing, stolen credentials) purely to
mislead the exploit belief. Because the defender's inference assumes every
infected host carries the exploited CVE, a decoy that does NOT carry the true CVE
is a poisoned "test": under a hard consistency belief it excludes the truth
outright. This is adversarial / noisy group testing --- the adversary corrupts
the test outcomes. SERUM's soft-likelihood belief is the defense: a few poisoned
observations down-weight rather than eliminate the true CVE.
"""

from __future__ import annotations

import numpy as np

from serum.sim.network import cve_prevalence


def choose_decoys(g, payload, k: int, rng: np.random.Generator | None = None) -> list:
    """Pick ``k`` decoy hosts that maximally mislead the exploit belief.

    Strategy: hosts that do NOT carry the true CVE (so a hard belief excludes the
    truth) and DO carry the most prevalent *other* CVE (to pull the posterior
    toward a plausible wrong exploit)."""
    rng = rng or np.random.default_rng()
    cve = payload.cve
    prev = cve_prevalence(g).copy()
    prev[cve] = -1.0
    target = int(prev.argmax())                    # the misdirection exploit

    best = [v for v, d in g.nodes(data=True)
            if target in d["vuln"] and cve not in d["vuln"]]
    if len(best) < k:                              # fall back to any non-carrier
        best = [v for v, d in g.nodes(data=True) if cve not in d["vuln"]]
    if not best:
        return []
    chosen = rng.choice(best, size=min(k, len(best)), replace=False)
    return [int(v) for v in chosen]
