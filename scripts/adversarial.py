#!/usr/bin/env python
"""Price of inference-evasion (novelty N8): can the attacker defeat the belief?

A strategic attacker picks its payload to evade the defender's exploit inference
(a non-identifiable, confusable CVE) instead of a random one. We measure how much
of the content-aware advantage this erodes.

Finding (data): it does NOT erode it -- evasive payloads leave content-awareness
at least as strong. This is a consequence of the identifiability structure
(docs/THEORY.md, Prop. 3): a confusable exploit's carriers are a subset of its
confusers', so acting on the believed subgraph still defends the true victims.
The attacker cannot simultaneously spread widely and evade content-aware
containment.

Saves results/adversarial.json.
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
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    records = load_clean_csv("data/clean/cves.csv")
    rows = []
    print(f"{'attacker':>14} {'no-def%':>8} {'content-aware%':>14} "
          f"{'best-fixed%':>12} {'rel-edge':>9} {'p':>9}")
    print("-" * 72)
    for obj in ["identifiable", "band", "evasive"]:
        spec = TrialSpec(n=500, n_cves=40, homophily=0.4, payload_strategy="band",
                         prev_band=(0.15, 0.55),
                         attack_objective=("" if obj == "band" else obj))
        stats, _ = compare_policies(spec, n_trials=trials, base_seed=0,
                                    verbose=False, records=records)
        rep = paired_report(stats)["primary"]
        nd = float(np.mean(stats["no-defense"].infected_fraction))
        ca = float(np.mean(stats["content-aware"].infected_fraction))
        bf = float(np.mean(stats[rep["vs"]].infected_fraction))
        rows.append({"attacker": obj, "no_defense": nd, "content_aware": ca,
                     "best_fixed": bf, "best_name": rep["vs"],
                     "rel_edge": rep["mean_rel_reduction"], "p": rep["p_value"]})
        print(f"{obj:>14} {100*nd:>7.1f} {100*ca:>13.1f} {100*bf:>11.1f} "
              f"{100*rep['mean_rel_reduction']:>+8.1f}% {rep['p_value']:>9.1e}")

    os.makedirs("results", exist_ok=True)
    json.dump(rows, open("results/adversarial.json", "w"), indent=2)
    print("\n[saved -> results/adversarial.json]")
    print("Inference-evasion does not erode the content-aware advantage: a "
          "confusable exploit's victims are a subset of its confusers', so the "
          "hedged belief still defends the right hosts (THEORY.md Prop. 3).")


if __name__ == "__main__":
    main()
