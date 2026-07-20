"""The attacker's payload: which vulnerability it weaponises and how hard.

A payload has one or more *target CVEs* plus a per-contact transmission
probability. In the single-CVE case (``Payload``) the worm exploits exactly
one vulnerability; in the multi-exploit case (``MultiPayload``) it carries an
*exploit set* and can infect any host that carries at least one CVE in that
set — a polymorphic / kitchen-sink worm. The defender never observes the
payload; it must be inferred from the shape of the outbreak (see
``serum.inference``). Both dataclasses expose the same
``can_infect(host_vuln)`` interface so the simulator is payload-agnostic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import numpy as np

from serum.sim.network import cve_prevalence


@dataclass(frozen=True)
class Payload:
    cve: int          # the vulnerability this worm exploits
    beta: float       # per-contact, per-step transmission probability

    def can_infect(self, host_vuln: frozenset) -> bool:
        return self.cve in host_vuln


@dataclass(frozen=True)
class MultiPayload:
    """A polymorphic worm carrying an *exploit set* — a hidden subset of the
    CVE universe. A host is vulnerable iff it carries at least one CVE in the
    set (an OR-of-exploits payload; the canonical "kitchen-sink" worm).

    Inference-side, this is the multi-defective analogue of vulnerability-
    gated identification: each propagation-infected host v is a positive
    test whose profile ``vuln(v)`` must intersect the true exploit set S*.
    So the posterior support after observing infected set I is the family of
    hitting sets: ``{S : ∀ v ∈ I, vuln(v) ∩ S ≠ ∅}``.
    """
    cves: frozenset   # the exploit set (a subset of the CVE universe)
    beta: float

    def __post_init__(self):
        # normalise so equality and hashing are canonical
        object.__setattr__(self, "cves", frozenset(int(c) for c in self.cves))

    @property
    def cve(self):
        """The payload's identity for plumbing that expects a single field
        (e.g. observation.captured_cve, EpisodeResult.payload_cve). Returns
        the whole exploit set — downstream code should not assume it is int."""
        return self.cves

    def can_infect(self, host_vuln: frozenset) -> bool:
        return bool(self.cves & host_vuln)


def make_multi_payload(cves: Iterable[int], beta: float = 0.35) -> MultiPayload:
    """Convenience constructor accepting any iterable of CVE ids."""
    return MultiPayload(cves=frozenset(int(c) for c in cves), beta=float(beta))


def sample_payload(
    g,
    beta: float = 0.35,
    strategy: str = "popular",
    rng: np.random.Generator | None = None,
    band: tuple = (0.20, 0.60),
) -> Payload:
    """Choose which CVE the attacker weaponises.

    strategy
    --------
    "popular"  : target the most widespread CVE (worst case for the fleet;
                 also where structure-only defenders waste the least budget,
                 i.e. the *hardest* case for our thesis -- a conservative test).
    "stealth"  : target a mid-prevalence CVE (structure-only defenders squander
                 budget on invulnerable hubs; the content-aware edge is largest).
    "band"     : sample *uniformly at random* among CVEs whose prevalence falls
                 in a "spreadable but not universal" band (default 20-60%). This
                 is the recommended evaluation strategy: it varies the target
                 across trials (no single hand-picked CVE) while keeping every
                 outbreak in the regime where containment is non-trivial.
    "random"   : uniformly random CVE.
    """
    rng = rng or np.random.default_rng()
    prev = cve_prevalence(g)
    if strategy == "popular":
        cve = int(prev.argmax())
    elif strategy == "stealth":
        order = np.argsort(prev)          # ascending prevalence
        cve = int(order[len(order) // 2])  # median-prevalence CVE
    elif strategy == "band":
        lo, hi = band
        cand = np.where((prev >= lo) & (prev <= hi))[0]
        if len(cand) == 0:  # relax to the middle third if the band is empty
            order = np.argsort(prev)
            third = max(1, len(order) // 3)
            cand = order[third:2 * third]
        cve = int(rng.choice(cand))
    elif strategy == "random":
        cve = int(rng.integers(g.graph["n_cves"]))
    else:
        raise ValueError(f"unknown payload strategy: {strategy!r}")
    # On real-data networks, ground transmissibility in the CVE's own CVSS-derived
    # rate rather than a single global beta.
    universe = g.graph.get("vuln_universe")
    if universe is not None:
        beta = float(universe.beta[cve])
    return Payload(cve=cve, beta=float(beta))
