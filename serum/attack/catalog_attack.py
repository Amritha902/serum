"""Attacking the *geometry of the defender's catalog*, and allocating against it.

Two attack surfaces are already modelled in ``serum.attack``: ``adversarial.py``
evades the defender's *estimator* (pick a confusable CVE so the belief cannot
pin it down) and ``adaptive.py`` poisons the defender's *belief* (plant decoy
infections). Both take the defender's asset inventory as given.

This module attacks the inventory itself. The open-world result
(``scripts/open_world.py``) showed that the content-aware advantage is governed
by **carrier-set proxy coverage** -- an unknown exploit is still contained if
some *known* vulnerability happens to live on the same machines. That immediately
implies an attacker move nobody has had to think about: don't pick the most
prevalent exploit, and don't pick the least identifiable one -- pick the one
sitting in the defender's **proxy blind spot**, where nothing in the catalog
covers the same hosts.

It also implies the defender's real decision is not which policy to run but
**which products to inventory**. No organisation inventories everything; asset
coverage is a budget. The conventional way to spend it is by popularity (cover
the software you have most of). Against a blind-spot attacker that is the wrong
objective: what matters is not how much of the fleet you can see, but whether
every *uncovered* vulnerability has a covered neighbour standing in for it.

The attacker's tradeoff is real, which is what makes this a game rather than a
free win. Blind-spot CVEs tend to be idiosyncratic, and idiosyncratic software
is installed on fewer hosts -- so the exploit that best evades content-awareness
is often one that cannot spread far. ``select_blindspot_payload`` therefore
optimises over CVEs that *can* still spread, and
``blindspot_frontier`` exposes the whole (spread, proxy) tradeoff so the
best response can be read off rather than asserted.
"""

from __future__ import annotations

import numpy as np

from serum.inference.identifiability import reachable_component
from serum.sim.catalog import _jaccard, catalog, true_carriers
from serum.sim.payload import Payload


def carrier_sets(g) -> dict:
    """Ground-truth carrier set for every CVE in the universe."""
    n = int(g.graph["n_cves"])
    return {c: true_carriers(g, c) for c in range(n)}


def jaccard_matrix(g, carriers: dict | None = None) -> np.ndarray:
    """``J[c, d]`` = carrier-set overlap between CVEs c and d.

    A *covered* CVE is fully inventoried, so its observed carrier set equals its
    true one; that is why this matrix can be computed from ground truth and still
    describe exactly what proxying the defender gets.
    """
    carriers = carriers or carrier_sets(g)
    n = int(g.graph["n_cves"])
    J = np.zeros((n, n), dtype=float)
    for c in range(n):
        for d in range(c + 1, n):
            j = _jaccard(carriers[c], carriers[d])
            J[c, d] = J[d, c] = j
    np.fill_diagonal(J, 1.0)
    return J


def spreading_cves(g, min_component: int = 20, spread_floor_frac: float = 0.0) -> list:
    """CVEs whose vulnerable subgraph is big enough to sustain an outbreak.

    ``spread_floor_frac`` additionally requires a CVE to reach at least that
    fraction of the *best* available exploit's component. Without it the
    "optimal" evader is whichever CVE is most obscure, which evades beautifully
    and infects nobody -- an attacker model that flatters the defender by
    letting the attacker choose to lose. A real attacker needs impact first and
    evasion second, so the choice set is restricted to exploits that can still
    do damage.
    """
    n = int(g.graph["n_cves"])
    comps = {c: len(reachable_component(g, c)) for c in range(n)}
    floor = float(min_component)
    if spread_floor_frac > 0.0 and comps:
        floor = max(floor, spread_floor_frac * max(comps.values()))
    return [c for c in range(n) if comps[c] >= floor]


def proxy_coverage(J: np.ndarray, covered, cve: int) -> float:
    """Best carrier-set stand-in for ``cve`` among the covered CVEs."""
    cov = [d for d in covered if d != cve]
    return float(max((J[cve, d] for d in cov), default=0.0))


def blindspot_frontier(g, covered=None, min_component: int = 20,
                       spread_floor_frac: float = 0.0) -> list:
    """The attacker's whole choice set as ``(cve, component, proxy_coverage)``.

    Sorted by proxy coverage ascending, so the head of the list is the blind
    spot and the tradeoff against spread capacity is visible rather than hidden
    inside an argmin.
    """
    covered = set(catalog(g) if covered is None else covered)
    J = jaccard_matrix(g)
    rows = []
    for c in spreading_cves(g, min_component, spread_floor_frac):
        rows.append((int(c),
                     len(reachable_component(g, c)),
                     proxy_coverage(J, covered, c)))
    rows.sort(key=lambda r: (r[2], -r[1]))
    return rows


def select_blindspot_payload(g, beta: float, covered=None,
                             min_component: int = 20,
                             spread_floor_frac: float = 0.5,
                             uncovered_only: bool = True,
                             rng: np.random.Generator | None = None) -> Payload:
    """The attacker's best response to a given inventory allocation.

    Chooses the spreading CVE with the least proxy coverage. With
    ``uncovered_only`` the attacker further restricts to CVEs the defender does
    not inventory at all -- the true zero-day case, where the defender has
    neither the signature nor a stand-in.
    """
    covered = set(catalog(g) if covered is None else covered)
    rows = blindspot_frontier(g, covered=covered, min_component=min_component,
                              spread_floor_frac=spread_floor_frac)
    if uncovered_only:
        rows = [r for r in rows if r[0] not in covered] or rows
    if not rows:
        c = int(np.argmax([len(reachable_component(g, k))
                           for k in range(int(g.graph["n_cves"]))]))
    else:
        c = rows[0][0]
    uni = g.graph.get("vuln_universe")
    b = float(uni.beta[c]) if uni is not None else float(beta)
    return Payload(cve=int(c), beta=b)


# -- how the defender spends its asset-coverage budget ---------------------

def allocate_prevalence(g, m: int, min_component: int = 20) -> frozenset:
    """Conventional allocation: inventory the ``m`` most widespread CVEs.

    This is what "improve our asset coverage" usually means in practice -- chase
    the software you have most of -- and it is the baseline the maximin
    allocation has to beat.
    """
    carriers = carrier_sets(g)
    order = sorted(carriers, key=lambda c: len(carriers[c]), reverse=True)
    return frozenset(order[:m])


def allocate_random(g, m: int, rng: np.random.Generator | None = None) -> frozenset:
    rng = rng or np.random.default_rng()
    n = int(g.graph["n_cves"])
    return frozenset(int(c) for c in rng.choice(n, size=min(m, n), replace=False))


def allocate_maximin_proxy(g, m: int, min_component: int = 20,
                           spread_floor_frac: float = 0.5) -> frozenset:
    """Greedy allocation that maximises the *worst* proxy coverage left uncovered.

    Objective: after choosing the covered set S, every spreading CVE outside S
    should have some member of S sitting on the same machines. Formally we
    greedily maximise ``min_{c not in S} max_{d in S} J[c, d]`` -- a maximin
    against an attacker who will pick the argmin. Submodular-flavoured but not
    submodular in general, so this is a heuristic; it needs no ground truth
    beyond the defender's own inventory, which is the point.
    """
    J = jaccard_matrix(g)
    threats = spreading_cves(g, min_component, spread_floor_frac)
    if not threats:
        return allocate_prevalence(g, m)

    covered: set = set()
    best_proxy = {c: 0.0 for c in threats}
    for _ in range(min(m, int(g.graph["n_cves"]))):
        best_d, best_score = None, -1.0
        for d in range(int(g.graph["n_cves"])):
            if d in covered:
                continue
            score = min(
                (max(best_proxy[c], J[c, d]) for c in threats if c != d and c not in covered),
                default=1.0,
            )
            if score > best_score:
                best_d, best_score = d, score
        if best_d is None:
            break
        covered.add(best_d)
        for c in threats:
            best_proxy[c] = max(best_proxy[c], J[c, best_d])
    return frozenset(covered)


def worst_case_proxy(g, covered, min_component: int = 20,
                     spread_floor_frac: float = 0.5) -> float:
    """The defender's exposure under an allocation: the attacker's argmin.

    Restricted to the same damage-capable choice set the attacker actually picks
    from, so the number describes exposure to a threat rather than to any
    obscure CVE the attacker would never bother weaponising."""
    J = jaccard_matrix(g)
    covered = set(covered)
    vals = [proxy_coverage(J, covered, c)
            for c in spreading_cves(g, min_component, spread_floor_frac)
            if c not in covered]
    return float(min(vals)) if vals else 1.0
