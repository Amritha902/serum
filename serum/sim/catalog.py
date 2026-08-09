"""Open-world containment: the exploit the worm uses need not be in your catalog.

Every result in SERUM up to this point assumes a **closed world**: the payload's
CVE is drawn from the same universe ``range(g.graph["n_cves"])`` that the
defender's belief ranges over (``serum.inference.belief.CVEBelief``). Under that
assumption the truth is always inside the posterior's support, so consistency
filtering can only ever *narrow* toward it and content-awareness is guaranteed
to be defending a superset of the real victims (Prop 3).

That assumption is exactly what a zero-day violates. A genuine zero-day is a
vulnerability that *exists in the fleet* -- hosts really do run the affected
software, and the worm really does exploit it -- but that is **absent from the
defender's vulnerability catalog**: no NVD entry, no scanner signature, no row
in the CMDB. The defender's asset inventory is not merely *noisy* about this
CVE (the ``serum.data.inventory`` channel); it is *silent* about it.

This module models that by *withholding* a CVE from the defender's view while
leaving ground truth untouched:

  * ``g.nodes[v]["vuln"]``          -- ground truth, drives spread. Unchanged.
  * ``g.nodes[v]["vuln_observed"]`` -- defender's view. The withheld CVE is
    stripped from every host, so from the defender's side the vulnerability
    simply does not exist anywhere in the fleet.

Why this is the interesting regime, and not just another noise knob
-------------------------------------------------------------------
Inventory *miss* noise removes a CVE from a random subset of hosts, so the
defender still has the CVE in its catalog and consistency filtering still
converges on it (with more samples). Catalog withholding removes it from
*every* host, which breaks the model in a qualitatively different way:

  1. The true CVE has **zero posterior mass at every step** -- no amount of
     evidence can recover it. The belief is not uncertain, it is *wrong*.
  2. Consistency filtering still returns a confident answer, drawn from the
     catalog CVEs that happen to be co-carried by the victims. The defender is
     therefore confidently defending the wrong vulnerable subgraph.
  3. In the worst case the content-aware agent takes **no action at all**:
     ``ContentAwareAgent`` scores a frontier host by the posterior mass on CVEs
     that host carries, drops every zero-scoring host, and returns ``[]`` when
     none score. A payload-blind heuristic never has this failure mode.

Detecting (2)/(3) online is what ``serum.inference.misspec`` does, and acting
on the detection is what ``serum.agents.openworld`` does.
"""

from __future__ import annotations

import numpy as np

from serum.data.inventory import defender_vuln


def withhold_from_catalog(g, cve: int):
    """Strip ``cve`` from the defender's view of every host, in place.

    Composes with ``apply_inventory_noise``: call this *after* it, so the
    withheld CVE is removed from the already-noisy view rather than from
    ground truth. Ground-truth ``vuln`` is never modified, so spread dynamics
    and the identifiability theory are unaffected.
    """
    cve = int(cve)
    for v in g.nodes():
        g.nodes[v]["vuln_observed"] = frozenset(defender_vuln(g, v) - {cve})
    known = set(range(int(g.graph["n_cves"]))) - {cve}
    g.graph["defender_catalog"] = frozenset(known)
    g.graph["withheld_cve"] = cve
    return g


def true_carriers(g, cve: int) -> set:
    """Hosts that really carry ``cve`` (ground truth, ignores the catalog)."""
    return {v for v, d in g.nodes(data=True) if cve in d["vuln"]}


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    u = len(a | b)
    return (len(a & b) / u) if u else 0.0


def proxy_overlap(g, cve: int, among=None) -> tuple:
    """How well the *rest* of the catalog stands in for ``cve``.

    Returns ``(best_cve, jaccard)`` for the catalog CVE whose carrier set most
    resembles ``cve``'s. This is the quantity that decides whether losing a CVE
    from the catalog actually costs the defender anything: a payload targeting
    an unknown vulnerability is still contained if some *known* vulnerability
    happens to live on the same machines, because defending either one defends
    the same subgraph.

    Note the defender can compute this statistic for every CVE in its own
    catalog *without any ground truth* -- it is a property of the asset
    inventory alone -- which is what makes it deployable as a zero-day exposure
    audit rather than a post-hoc explanation.
    """
    target = true_carriers(g, cve)
    pool = sorted(among) if among is not None else sorted(catalog(g))
    best, best_j = None, -1.0
    for c in pool:
        if c == cve:
            continue
        j = _jaccard(target, {v for v in g.nodes() if c in defender_vuln(g, v)})
        if j > best_j:
            best, best_j = c, j
    return best, (best_j if best_j >= 0 else 0.0)


def withhold_confusable(g, cve: int, j: int = 0):
    """Withhold ``cve`` *and* its ``j`` closest carrier-set proxies.

    ``j = 0`` reproduces :func:`withhold_from_catalog`: a single unknown
    vulnerability, with the rest of the catalog free to proxy for it. Raising
    ``j`` progressively strips away those proxies, which is the realistic model
    of a zero-day in **novel software** -- not one missing CVE row, but a whole
    product the defender has never inventoried, so nothing in the catalog sits
    on the same machines.

    Returns ``(withheld_set, residual_overlap)`` where ``residual_overlap`` is
    the best remaining Jaccard proxy after withholding -- the explanatory
    variable for how much content-awareness degrades.
    """
    cve = int(cve)
    target = true_carriers(g, cve)
    others = []
    for c in sorted(catalog(g)):
        if c == cve:
            continue
        carriers = {v for v in g.nodes() if c in defender_vuln(g, v)}
        others.append((_jaccard(target, carriers), c))
    others.sort(reverse=True)
    withheld = {cve} | {c for _, c in others[: max(0, int(j))]}

    for v in g.nodes():
        g.nodes[v]["vuln_observed"] = frozenset(defender_vuln(g, v) - withheld)
    g.graph["defender_catalog"] = frozenset(
        set(range(int(g.graph["n_cves"]))) - withheld
    )
    g.graph["withheld_cve"] = cve
    g.graph["withheld_set"] = frozenset(withheld)

    _, residual = proxy_overlap(g, cve)
    g.graph["residual_proxy"] = float(residual)
    return withheld, float(residual)


def restrict_catalog(g, covered):
    """Set the defender's catalog to exactly ``covered``, in place.

    Where :func:`withhold_confusable` models "one unknown thing", this models the
    standing condition of every real security organisation: asset coverage is a
    *budget*, not a boolean. No CMDB inventories every product, so the catalog is
    always a strict subset of what is actually running, and the interesting
    question is not whether there are gaps but **which** gaps you choose to have.
    Ground truth is untouched; only the defender's view narrows.
    """
    covered = frozenset(int(c) for c in covered)
    for v in g.nodes():
        g.nodes[v]["vuln_observed"] = frozenset(g.nodes[v]["vuln"] & covered)
    g.graph["defender_catalog"] = covered
    g.graph.pop("withheld_cve", None)
    g.graph.pop("withheld_set", None)
    return g


def catalog(g) -> frozenset:
    """The CVEs the defender's catalog knows about (all of them by default)."""
    c = g.graph.get("defender_catalog")
    return c if c is not None else frozenset(range(int(g.graph["n_cves"])))


def is_open_world(g) -> bool:
    """True when the payload's CVE has been withheld from the defender."""
    return g.graph.get("withheld_cve") is not None


def observed_prevalence(g) -> np.ndarray:
    """Prevalence of each CVE *as the defender's catalog sees it*.

    Used as the null-hypothesis base rate by the misspecification monitor: how
    often would an arbitrary host carry CVE ``c`` by coincidence, if ``c`` were
    not the thing actually driving the outbreak?
    """
    n_cves = int(g.graph["n_cves"])
    counts = np.zeros(n_cves, dtype=float)
    for v in g.nodes():
        for c in defender_vuln(g, v):
            counts[c] += 1.0
    return counts / max(1, g.number_of_nodes())
