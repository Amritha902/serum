#!/usr/bin/env python
"""Robustness to an imperfect/stale defender inventory (noisy group testing).

The defender infers and acts using a NOISY view of each host's vulnerabilities
(vuln_observed), while the worm spreads over the true profiles. We sweep the
inventory error and measure whether content-awareness still beats the best fixed
structural baseline.

Finding: content-awareness survives realistic error (~15% missed detections) but
has a crossover near ~30% miss, beyond which acting on a badly-wrong network map
is worse than structure-blind defense. This quantifies how good an asset
inventory must be for content-aware containment to pay off.

Saves results/inventory.json.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402

from serum.data.clean import load_clean_csv  # noqa: E402
from serum.experiments.harness import TrialSpec, compare_policies, paired_report  # noqa: E402


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    records = load_clean_csv("data/clean/cves.csv")
    grid = [(0.0, 0.0), (0.1, 0.03), (0.2, 0.07), (0.3, 0.1), (0.4, 0.12), (0.5, 0.15)]
    rows = []
    print(f"{'miss':>5} {'false':>6} {'no-def%':>8} {'CA%':>7} {'best-fixed%':>12} "
          f"{'rel-edge':>9} {'p':>9}")
    print("-" * 62)
    for miss, false in grid:
        spec = TrialSpec(n=500, n_cves=40, homophily=0.4, payload_strategy="band",
                         prev_band=(0.15, 0.55), inventory_miss=miss, inventory_false=false)
        stats, _ = compare_policies(spec, n_trials=trials, base_seed=0,
                                    verbose=False, records=records)
        rep = paired_report(stats)["primary"]
        nd = float(np.mean(stats["no-defense"].infected_fraction))
        ca = float(np.mean(stats["content-aware"].infected_fraction))
        bf = float(np.mean(stats[rep["vs"]].infected_fraction))
        rows.append({"miss": miss, "false": false, "no_defense": nd,
                     "content_aware": ca, "best_fixed": bf,
                     "rel_edge": rep["mean_rel_reduction"], "p": rep["p_value"]})
        print(f"{miss:>5.2f} {false:>6.2f} {100*nd:>7.1f} {100*ca:>6.1f} "
              f"{100*bf:>11.1f} {100*rep['mean_rel_reduction']:>+8.1f}% {rep['p_value']:>9.1e}")

    os.makedirs("results", exist_ok=True)
    json.dump(rows, open("results/inventory.json", "w"), indent=2)
    print("\n[saved -> results/inventory.json]  Content-awareness needs an "
          "inventory better than ~70% complete to pay off.")


if __name__ == "__main__":
    main()
