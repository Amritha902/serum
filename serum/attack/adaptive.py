"""Audit-aware best-response poisoning against the RobustAgent's trust audit.

SR5 in the review backlog: the poison-robustness result (``scripts/robust.py``)
was evaluated against a *naive* poisoner (``attack/deception.py``) that plants
decoys carrying the most-prevalent *other* CVE, with no regard for the defender's
audit. A reviewer's fair objection: that attacker is a strawman we built to lose.
This module builds the attacker that **best-responds to the audit rule itself**.

The audit (see ``agents/robust.py``). RobustAgent keeps a trust weight
``alpha`` that each step moves toward the fraction of new *real* propagation
infections carrying its current MAP CVE. Real spread is gated on the true payload
``c*``, so every real infection carries ``c*``. Thus for a poisoned belief whose
MAP is a decoy CVE ``c'``, the audit's pass rate converges to the **carrier
overlap**::

    overlap(c') = |carriers(c*) & carriers(c')| / |carriers(c*)|
                = P(host carries c'  |  host carries c*).

A naive poisoner picks ``c'`` with near-zero overlap (a disjoint prevalent CVE):
real spread then contradicts the poisoned MAP, ``alpha`` collapses, and the agent
degrades safely to structure-only. **That is why naive poisoning fails.**

The best response. To keep ``alpha`` high the attacker must pick ``c'`` whose
carriers *overlap* the true victims as much as possible -- but pure maximal
overlap is self-defeating: if ``carriers(c*) ⊆ carriers(c')`` then defending the
``c'`` subgraph *over-covers* the true victims (Prop. 3, confusability = subset
order), so the attacker gains nothing. The damaging regime is the knife-edge:
overlap high enough to keep ``alpha`` above the agent's patch/commit threshold,
yet ``carriers(c') `` still *missing* a chunk of the true victims
``leak(c') = carriers(c*) \\ carriers(c')`` that a confident ``c'``-defender then
leaves open. The best-response CVE maximises a damage score that rewards *both*
keeping the audit passing (overlap) and leaking true victims (leak):

    damage(c') = overlap(c') * |leak(c')|.

Decoys are planted on ``leak``-adjacent carriers of ``c'`` that do *not* carry
``c*`` (so the belief's MAP is pulled toward ``c'`` while every planted host is a
genuine consistency violation for the truth).

Honest note. This is a best response on the *placement* channel against a *known*
audit rule -- a strong, white-box adversary. Whether it actually defeats the
robust agent is an empirical question answered in ``scripts/adaptive_attack.py``;
theory (Prop. 3) predicts the overlap/leak trade-off caps the attacker's gain.
"""

from __future__ import annotations

import numpy as np

from serum.sim.network import cve_prevalence


def _carrier_sets(g):
    """Map every CVE index to the set of hosts carrying it (ground-truth vuln)."""
    carriers: dict[int, set] = {}
    for v, d in g.nodes(data=True):
        for c in d["vuln"]:
            carriers.setdefault(int(c), set()).add(v)
    return carriers


def best_response_cve(g, payload, tau: float = 0.5):
    """The misdirection CVE that best-responds to the trust audit.

    Returns ``(c_prime, overlap, leak)`` for the CVE maximising
    ``overlap * leak`` among candidates whose overlap clears ``tau`` (so the
    audit keeps ``alpha`` up); if none clears ``tau`` it returns the
    highest-overlap candidate (the closest the attacker can get to keeping the
    audit passing). Returns ``None`` if no usable misdirection CVE exists.
    """
    carriers = _carrier_sets(g)
    cve = int(payload.cve)
    truth = carriers.get(cve, set())
    if not truth:
        return None

    scored = []          # (damage, overlap, leak, c')
    fallback = []        # (overlap, leak, c') for the below-tau case
    for c, car in carriers.items():
        if c == cve or not car:
            continue
        inter = len(truth & car)
        if inter == 0:
            continue                       # disjoint -> audit collapses alpha; skip
        overlap = inter / len(truth)
        leak = len(truth - car)
        if leak == 0:
            continue                       # superset -> over-covers truth (Prop. 3); useless
        fallback.append((overlap, leak, c))
        if overlap >= tau:
            scored.append((overlap * leak, overlap, leak, c))

    if scored:
        _, overlap, leak, c = max(scored, key=lambda r: r[0])
        return c, overlap, leak
    if fallback:
        overlap, leak, c = max(fallback, key=lambda r: r[0])
        return c, overlap, leak
    return None


def choose_decoys_adaptive(g, payload, k: int, rng=None, tau: float = 0.5) -> list:
    """Pick ``k`` decoy hosts that best-respond to the RobustAgent's trust audit.

    Plants decoys carrying the best-response misdirection CVE ``c'`` (and not the
    true CVE) -- these poison the belief toward ``c'`` while keeping the audit
    overlap as high as the overlap/leak trade-off allows. Falls back to the naive
    prevalence poisoner if no usable ``c'`` exists.
    """
    rng = rng or np.random.default_rng()
    br = best_response_cve(g, payload, tau=tau)
    if br is None:
        from serum.attack.deception import choose_decoys
        return choose_decoys(g, payload, k, rng=rng)

    c_prime, _, _ = br
    cve = int(payload.cve)
    pool = [v for v, d in g.nodes(data=True)
            if c_prime in d["vuln"] and cve not in d["vuln"]]
    if not pool:
        from serum.attack.deception import choose_decoys
        return choose_decoys(g, payload, k, rng=rng)
    chosen = rng.choice(pool, size=min(k, len(pool)), replace=False)
    return [int(v) for v in chosen]
