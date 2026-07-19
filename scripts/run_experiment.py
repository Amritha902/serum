#!/usr/bin/env python
"""Headline experiment: does content-awareness beat structure-only containment?

Runs the full policy lineup over many paired outbreaks and reports, per policy,
the mean fraction of the fleet infected (lower is better), the availability it
preserved, and how quickly it contained the worm. Saves:

    results/summary.json      machine-readable stats
    results/infection_curves.png   mean outbreak trajectory per policy

Usage:
    python scripts/run_experiment.py --trials 30 --topology ba --strategy stealth
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# allow running from repo root without install
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from serum.experiments.harness import (  # noqa: E402
    TrialSpec, compare_policies, paired_report,
)


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--trials", type=int, default=30)
    p.add_argument("--n", type=int, default=500, help="hosts per network")
    p.add_argument("--topology", default="ba", choices=["ba", "ws", "er", "rgg"])
    p.add_argument("--strategy", default="stealth", choices=["popular", "stealth", "random"])
    p.add_argument("--beta", type=float, default=0.35)
    p.add_argument("--budget", type=int, default=5)
    p.add_argument("--horizon", type=int, default=40)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--outdir", default="results")
    p.add_argument("--no-plot", action="store_true")
    return p.parse_args()


def print_table(stats):
    order = [
        "no-defense", "random", "acquaintance", "degree", "eigenvector",
        "betweenness", "greedy-blocking", "content-aware", "content-aware-oracle",
    ]
    rows = [stats[n].summary() for n in order if n in stats]
    w = 22
    print("\n" + "=" * 78)
    print(f"{'policy':<{w}}{'infected %':>14}{'availability':>16}{'contain@step':>16}")
    print("-" * 78)
    for r in rows:
        inf_m, inf_s = r["infected_fraction"]
        av_m, _ = r["availability"]
        st_m, _ = r["steps_to_containment"]
        print(f"{r['name']:<{w}}{100*inf_m:>10.1f}±{100*inf_s:<3.0f}"
              f"{100*av_m:>14.1f}%{st_m:>16.1f}")
    print("=" * 78)


def save_plot(curves, outdir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:  # pragma: no cover
        print(f"[plot skipped: {e}]")
        return
    import numpy as np

    plt.figure(figsize=(8, 5))
    order = ["no-defense", "random", "acquaintance", "degree", "eigenvector",
             "betweenness", "greedy-blocking", "content-aware", "content-aware-oracle"]
    styles = {
        "no-defense": ("#9e9e9e", "-"),
        "random": ("#b39ddb", "-"),
        "acquaintance": ("#ce93d8", "-"),
        "degree": ("#4fc3f7", "-"),
        "eigenvector": ("#4dd0e1", "-"),
        "betweenness": ("#4db6ac", "-"),
        "greedy-blocking": ("#66bb6a", "-"),
        "content-aware": ("#e53935", "-"),
        "content-aware-oracle": ("#e53935", "--"),
    }
    for name in order:
        if name not in curves:
            continue
        traces = curves[name]
        maxlen = max(len(t) for t in traces)
        padded = np.array([t + [t[-1]] * (maxlen - len(t)) for t in traces], dtype=float)
        mean_curve = padded.mean(axis=0)
        color, ls = styles.get(name, ("#333", "-"))
        lw = 2.6 if "content-aware" in name else 1.6
        plt.plot(mean_curve, label=name, color=color, linestyle=ls, linewidth=lw)
    plt.xlabel("time step")
    plt.ylabel("infected hosts")
    plt.title("Outbreak trajectory under each containment policy")
    plt.legend(frameon=False, fontsize=9)
    plt.tight_layout()
    path = os.path.join(outdir, "infection_curves.png")
    plt.savefig(path, dpi=140)
    print(f"[saved plot -> {path}]")


def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    spec = TrialSpec(
        n=args.n,
        topology=args.topology,
        beta=args.beta,
        payload_strategy=args.strategy,
        budget_per_step=args.budget,
        horizon=args.horizon,
    )
    print(f"Running {args.trials} paired outbreaks "
          f"[n={spec.n} topo={spec.topology} strategy={spec.payload_strategy} "
          f"beta={spec.beta} budget={spec.budget_per_step}] ...")
    stats, curves = compare_policies(spec, n_trials=args.trials, base_seed=args.seed)
    print_table(stats)

    report = paired_report(stats)
    if report:
        n = report["n_trials"]
        for kind in ("primary", "ensemble"):
            r = report[kind]
            lo, hi = r["ci95_abs"]
            label = "PRIMARY (vs best fixed baseline)" if kind == "primary" \
                else "STRESS  (vs per-trial ensemble oracle)"
            print(f"\n{label}: content-aware vs {r['vs']} (paired, n={n})")
            print(f"  reduction: {100*r['mean_abs_reduction']:.2f} pts "
                  f"(95% CI [{100*lo:.2f}, {100*hi:.2f}]); "
                  f"rel {100*r['mean_rel_reduction']:.1f}%")
            print(f"  wins {r['wins']}/{n}; Wilcoxon p = {r['p_value']:.2e}")

    summary = {name: s.summary() for name, s in stats.items()}
    summary["_spec"] = vars(spec)
    summary["_paired_report"] = report
    with open(os.path.join(args.outdir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    print(f"[saved stats -> {os.path.join(args.outdir, 'summary.json')}]")

    if not args.no_plot:
        save_plot(curves, args.outdir)


if __name__ == "__main__":
    main()
