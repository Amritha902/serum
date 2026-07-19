"""The attacker's payload: which vulnerability it weaponises and how hard.

A payload is deliberately minimal here -- a single target CVE plus a
per-contact transmission probability. The defender does *not* observe the
payload; it must be inferred from the shape of the outbreak (see
``serum.inference``). Richer payloads (multi-CVE, polymorphic, dwell-time)
are a planned extension and slot in behind this interface.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from serum.sim.network import cve_prevalence


@dataclass(frozen=True)
class Payload:
    cve: int          # the vulnerability this worm exploits
    beta: float       # per-contact, per-step transmission probability

    def can_infect(self, host_vuln: frozenset) -> bool:
        return self.cve in host_vuln


def sample_payload(
    g,
    beta: float = 0.35,
    strategy: str = "popular",
    rng: np.random.Generator | None = None,
) -> Payload:
    """Choose which CVE the attacker weaponises.

    strategy
    --------
    "popular"  : target the most widespread CVE (worst case for the fleet;
                 also where structure-only defenders waste the least budget,
                 i.e. the *hardest* case for our thesis -- a conservative test).
    "stealth"  : target a mid-prevalence CVE (structure-only defenders squander
                 budget on invulnerable hubs; the content-aware edge is largest).
    "random"   : uniformly random CVE.
    """
    rng = rng or np.random.default_rng()
    prev = cve_prevalence(g)
    if strategy == "popular":
        cve = int(prev.argmax())
    elif strategy == "stealth":
        order = np.argsort(prev)          # ascending prevalence
        cve = int(order[len(order) // 2])  # median-prevalence CVE
    elif strategy == "random":
        cve = int(rng.integers(g.graph["n_cves"]))
    else:
        raise ValueError(f"unknown payload strategy: {strategy!r}")
    return Payload(cve=cve, beta=float(beta))
