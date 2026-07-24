"""Invariants of the audit-aware best-response poisoner (SR5, attack/adaptive.py).

The adaptive attacker must (a) plant decoys that are genuine consistency
violations for the true payload (they do NOT carry the true CVE), and (b) prefer
a misdirection CVE that overlaps the true victims (to keep the trust audit
passing) yet leaks some of them (else defending it over-covers the truth and the
attack is pointless). These are the properties that make it a real best response
rather than the naive prevalence poisoner.
"""
from __future__ import annotations

import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from serum.attack.adaptive import best_response_cve, choose_decoys_adaptive
from serum.sim.network import generate_network
from serum.sim.payload import sample_payload


def make(seed=0, n=300, n_cves=16):
    rng = np.random.default_rng(seed)
    g = generate_network(n=n, n_cves=n_cves, vuln_lambda=6.0,
                         popularity_alpha=0.8, rng=rng)
    payload = sample_payload(g, beta=0.35, strategy="band", band=(0.15, 0.55), rng=rng)
    return g, payload, rng


def _carriers(g, c):
    return {v for v, d in g.nodes(data=True) if c in d["vuln"]}


def test_decoys_never_carry_true_cve():
    """Every planted decoy is a genuine poison: it lacks the true payload CVE."""
    for seed in range(6):
        g, payload, rng = make(seed)
        decoys = choose_decoys_adaptive(g, payload, k=15, rng=rng)
        for v in decoys:
            assert payload.cve not in g.nodes[v]["vuln"]


def test_decoys_are_distinct_and_bounded():
    g, payload, rng = make(1)
    decoys = choose_decoys_adaptive(g, payload, k=12, rng=rng)
    assert len(decoys) == len(set(decoys))
    assert len(decoys) <= 12


def test_best_response_overlaps_and_leaks():
    """When a best-response CVE exists it must overlap the truth (keep alpha up)
    and leak some true victims (or the attack over-covers and is useless)."""
    found = 0
    for seed in range(10):
        g, payload, _ = make(seed)
        br = best_response_cve(g, payload)
        if br is None:
            continue
        found += 1
        c_prime, overlap, leak = br
        truth = _carriers(g, payload.cve)
        carcp = _carriers(g, c_prime)
        # overlap is the audit pass-rate = P(carry c' | carry c*)
        assert overlap == pytest.approx(len(truth & carcp) / len(truth))
        assert 0.0 < overlap <= 1.0
        # leak > 0: the misdirection is NOT a superset of the truth
        assert leak > 0
        assert not truth <= carcp
    assert found >= 1, "expected at least one solvable best-response instance"


def test_adaptive_differs_from_naive_placement():
    """The audit-aware placement should generally not equal the naive one
    (otherwise 'adaptive' adds nothing)."""
    from serum.attack.deception import choose_decoys
    differ = 0
    for seed in range(8):
        g, payload, _ = make(seed)
        a = set(choose_decoys_adaptive(g, payload, k=20,
                                       rng=np.random.default_rng(seed)))
        n = set(choose_decoys(g, payload, k=20, rng=np.random.default_rng(seed)))
        if a != n:
            differ += 1
    assert differ >= 1
