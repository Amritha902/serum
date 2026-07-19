"""Imperfect / stale defender inventory.

In reality a defender does not know every device's software exactly: asset
scanners miss services, firmware versions drift, CVE-to-product mappings are
incomplete. SERUM models this by giving the defender an *observed* vulnerability
view ``vuln_observed`` that differs from the ground-truth ``vuln`` the worm
actually exploits. The spread and the identifiability theory use the true
profiles; the defender's belief and content-aware policy use only the observed
ones. This tests whether content-awareness survives realistic inventory error.

Two error channels:
  * ``miss``  — a true vulnerability is absent from the defender's view
    (undetected / unscanned service). This is the dangerous one: the defender
    under-estimates a host's exposure.
  * ``false`` — a vulnerability the host does not have appears in the view
    (stale record / misattributed CPE). This wastes budget but is less harmful.
"""

from __future__ import annotations

import numpy as np


def apply_inventory_noise(g, miss: float = 0.15, false: float = 0.05,
                          rng: np.random.Generator | None = None):
    """Attach a noisy defender view ``vuln_observed`` to every host, in place."""
    rng = rng or np.random.default_rng()
    n_cves = g.graph["n_cves"]
    for v in g.nodes():
        true = g.nodes[v]["vuln"]
        obs = {c for c in true if rng.random() >= miss}          # miss detections
        if false > 0:
            for c in range(n_cves):
                if c not in true and rng.random() < false:       # stale/false entries
                    obs.add(c)
        g.nodes[v]["vuln_observed"] = frozenset(obs)
    g.graph["inventory_miss"] = float(miss)
    g.graph["inventory_false"] = float(false)
    return g


def defender_vuln(g, v):
    """The defender's (possibly imperfect) view of host ``v``'s vulnerabilities.
    Falls back to ground truth when no noisy inventory has been applied."""
    d = g.nodes[v]
    return d["vuln_observed"] if "vuln_observed" in d else d["vuln"]


def defender_prevalence(g) -> np.ndarray:
    """CVE prevalence as the defender estimates it from its observed inventory."""
    n_cves = g.graph["n_cves"]
    counts = np.zeros(n_cves, dtype=float)
    for v in g.nodes():
        for c in defender_vuln(g, v):
            counts[c] += 1.0
    return counts / g.number_of_nodes()
