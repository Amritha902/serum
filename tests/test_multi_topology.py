"""Tests for the multi-topology generalization experiment.

We check the plumbing (run_topology returns a well-formed report, saved JSON
loads cleanly) on a *synthetic* BA graph so the test needs no network access.
A second test verifies the checked-in ``results/real/snap_topologies.json``
matches the claim in DEVLOG/BACKLOG (content-aware beats the best structural
baseline on both SNAP topologies).
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.multi_topology import build_spec, run_topology
from tests.test_data import _corpus

RESULTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "results", "real", "snap_topologies.json")


def test_build_spec_carries_topology_and_defaults():
    for topo in ("email", "as", "ba"):
        spec = build_spec(topo)
        assert spec.topology == topo
        assert spec.budget_per_step == 3
        assert spec.horizon == 60
        assert spec.payload_strategy == "band"


def test_run_topology_smoke_on_synthetic():
    """The multi_topology harness returns a full policy set + paired report on
    a synthetic BA graph. Exercises the same code path as the SNAP run without
    touching the network."""
    records = _corpus(80)
    res = run_topology("ba", records, trials=3, budget=3, horizon=20)
    assert res["topology"] == "ba"
    assert res["trials"] == 3
    for name in ("no-defense", "degree", "betweenness", "content-aware",
                 "greedy-blocking"):
        assert name in res["policies"], name
        s = res["policies"][name]
        # summary() gives (mean, stdev) — JSON-serialised to a length-2 list
        assert len(s["infected_fraction"]) == 2
    rep = res["paired_report"]
    assert rep is not None
    assert rep["n_trials"] == 3
    for kind in ("primary", "ensemble"):
        r = rep[kind]
        assert "vs" in r
        assert "mean_abs_reduction" in r
        lo, hi = r["ci95_abs"]
        assert lo <= hi


def test_snap_topologies_json_matches_flagship_claim():
    """The checked-in SNAP multi-topology result must show that content-aware
    reaches at-least-as-low infection as the best structural baseline on BOTH
    topologies (the flagship generalization claim). If this fails, either the
    artifact is stale (rerun scripts/multi_topology.py) or the win no longer
    holds and BACKLOG/DEVLOG must be updated."""
    if not os.path.exists(RESULTS):
        pytest.skip(f"{RESULTS} not present; run scripts/multi_topology.py")
    with open(RESULTS) as f:
        payload = json.load(f)
    tops = payload["topologies"]
    assert set(tops) == {"email", "as"}, sorted(tops)
    struct_names = ("degree", "eigenvector", "betweenness", "greedy-blocking",
                    "acquaintance")
    for topo, res in tops.items():
        pols = res["policies"]
        ca_mean = pols["content-aware"]["infected_fraction"][0]
        struct_means = [pols[n]["infected_fraction"][0]
                        for n in struct_names if n in pols]
        best_struct = min(struct_means)
        # content-aware must not be *worse* than the best structural baseline
        assert ca_mean <= best_struct + 1e-6, (
            f"{topo}: content-aware {ca_mean:.4f} worse than "
            f"best structural {best_struct:.4f}")
        # and the paired win must be positive on the mean reduction
        rep = res["paired_report"]
        assert rep is not None
        assert rep["primary"]["mean_abs_reduction"] >= 0, (
            f"{topo}: paired mean reduction negative "
            f"({rep['primary']['mean_abs_reduction']:.4f})")
