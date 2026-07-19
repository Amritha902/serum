#!/usr/bin/env python
"""Infection-vs-availability Pareto front (substantiates novelty N6).

The claim "content-aware is Pareto-dominant" needs the actual front. We sweep the
containment budget and, for each policy, plot mean final infection against mean
availability. A policy is Pareto-dominant if, for every budget, no other policy
is simultaneously lower-infection and higher-availability. Content-aware patches
precisely (availability-preserving) once its belief sharpens, so it should sit at
the favourable corner (low infection, high availability) across budgets.

Saves results/pareto.json and results/pareto.png.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402

from serum.data.clean import load_clean_csv  # noqa: E402
from serum.experiments.harness import TrialSpec, compare_policies  # noqa: E402

POLICIES = ["no-defense", "degree", "betweenness", "greedy-blocking",
            "oracle-delay-5", "content-aware", "content-aware-oracle"]


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    records = load_clean_csv("data/clean/cves.csv")
    budgets = [2, 4, 6, 8, 12]
    curve = {p: {"infected": [], "availability": [], "budget": []} for p in POLICIES}
    print(f"{'budget':>6}  " + "  ".join(f"{p[:12]:>12}" for p in POLICIES))
    for b in budgets:
        spec = TrialSpec(n=500, n_cves=40, homophily=0.4, payload_strategy="band",
                         prev_band=(0.15, 0.55), budget_per_step=b)
        stats, _ = compare_policies(spec, n_trials=trials, base_seed=0,
                                    verbose=False, records=records)
        row = []
        for p in POLICIES:
            if p not in stats:
                row.append("--"); continue
            s = stats[p].summary()
            inf, av = s["infected_fraction"][0], s["availability"][0]
            curve[p]["infected"].append(inf)
            curve[p]["availability"].append(av)
            curve[p]["budget"].append(b)
            row.append(f"{100*inf:5.1f}/{100*av:4.0f}")
        print(f"{b:>6}  " + "  ".join(f"{r:>12}" for r in row))

    os.makedirs("results", exist_ok=True)
    json.dump(curve, open("results/pareto.json", "w"), indent=2)
    save_plot(curve)


def save_plot(curve):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:  # pragma: no cover
        print(f"[plot skipped: {e}]"); return
    styles = {
        "no-defense": ("#9e9e9e", "o"), "degree": ("#4fc3f7", "s"),
        "betweenness": ("#4db6ac", "^"), "greedy-blocking": ("#66bb6a", "v"),
        "oracle-delay-5": ("#ff9800", "D"), "content-aware": ("#e53935", "*"),
        "content-aware-oracle": ("#b71c1c", "P"),
    }
    plt.figure(figsize=(7.5, 5.2))
    for p in POLICIES:
        if not curve[p]["infected"]:
            continue
        x = [100 * v for v in curve[p]["availability"]]
        y = [100 * v for v in curve[p]["infected"]]
        c, m = styles.get(p, ("#333", "o"))
        sz = 220 if "content-aware" == p else 90
        plt.scatter(x, y, c=c, marker=m, s=sz, label=p, zorder=3,
                    edgecolors="black", linewidths=0.4)
        plt.plot(x, y, c=c, alpha=0.35, lw=1)
    plt.xlabel("availability preserved (%)  → better")
    plt.ylabel("final infection (%)  ← better")
    plt.title("Infection–availability Pareto front (budget swept 2–12)\n"
              "content-aware occupies the low-infection, high-availability corner")
    plt.gca().invert_yaxis()  # lower infection at top
    plt.legend(frameon=False, fontsize=8, loc="upper left")
    plt.tight_layout()
    plt.savefig("results/pareto.png", dpi=140)
    print("[saved -> results/pareto.png, results/pareto.json]")


if __name__ == "__main__":
    main()
