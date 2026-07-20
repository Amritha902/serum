#!/usr/bin/env python
"""Diversity-for-observability (P2).

Question. Given a budget B of canary hosts the defender can provision (each a
fresh machine with a chosen software profile), can we engineer the fleet so
outbreaks self-reveal — i.e. so identifiable_fraction jumps close to 1.0?

Method. On real NVD-derived fleets (K CVEs, n hosts, homophily-clustered
software), we compare two canary planners:

  * **greedy** — at each step, pick a currently-unidentifiable CVE and install
    a singleton ``{c}`` canary that pins it. In *operational* mode the canary
    is attached to a host in c's reachable vulnerable component so the augment
    is visible to a saturating outbreak.
  * **random**  — same shape (singleton canaries) but the CVE is uniform
    random over [K], no dominance-aware ranking.

Both are monotone (canaries only *break* subset-order dominances; see
docs/THEORY.md for the argument), so both curves are non-decreasing in B.
The gap is the value of dominance-awareness.

Reported per network: identifiable-fraction curve (both global and
operational) for B ∈ {0, 1, 2, 4, 8, 12, 16, 20, 25, 30}, and the minimum B
needed to reach 100% under each planner. Aggregated across trials as mean ±
std, with paired sign-tests of greedy vs random at every B.

Outputs (idempotent): ``results/diversity.json``, ``results/diversity.png``.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402

from serum.data.clean import load_clean_csv  # noqa: E402
from serum.data.profiles import generate_real_network  # noqa: E402
from serum.inference.diversity import (  # noqa: E402
    budget_to_full_identifiability, identifiability_curve,
)
from serum.inference.identifiability import (  # noqa: E402
    carriers, confusability_graph, is_identifiable,
)
from serum.sim.network import generate_network  # noqa: E402


BUDGETS = [0, 1, 2, 4, 8, 12, 16, 20, 25, 30]


def _initial_ident(g):
    K = g.graph["n_cves"]
    live = [c for c in range(K) if carriers(g, c)]
    if not live:
        return 0, 0, 0
    cg = confusability_graph(g)
    i0_global = sum(1 for c in live if cg.out_degree(c) == 0)
    i0_op = sum(1 for c in live if is_identifiable(g, c))
    return len(live), i0_global, i0_op


def _paired_sign_test(deltas):
    """Return (wins, ties, losses) where win = greedy > random at this B.
    Positive deltas favour greedy. Simple, doesn't assume a distribution."""
    d = np.asarray(deltas)
    return int((d > 0).sum()), int((d == 0).sum()), int((d < 0).sum())


def run(trials: int, K: int, n: int, use_real: bool):
    have_real = os.path.exists("data/clean/cves.csv")
    if use_real and have_real:
        records = load_clean_csv("data/clean/cves.csv")
        data_source = "real"
    else:
        records = None
        data_source = "synthetic"

    per_trial = []
    print(f"diversity: {trials} trials, K={K}, n={n}, {data_source}")
    print(f"{'trial':>5} {'live':>5} {'I0g':>5} {'I0o':>5} "
          f"{'B*g_glob':>8} {'B*r_glob':>8} {'B*g_op':>7} {'B*r_op':>7}")

    for t in range(trials):
        rng = np.random.default_rng(1000 + t)
        if records is not None:
            g = generate_real_network(records, n=n, n_cves=K, n_products=max(60, 2 * K),
                                      homophily=0.4, rng=rng)
        else:
            g = generate_network(n=n, n_cves=K, vuln_lambda=5,
                                 popularity_alpha=0.7, rng=rng)
        live, i0_g, i0_o = _initial_ident(g)
        if live == 0:
            continue

        greedy_glob = identifiability_curve(g, BUDGETS, mode="global", strategy="greedy")
        greedy_op = identifiability_curve(g, BUDGETS, mode="operational", strategy="greedy")
        random_glob = identifiability_curve(g, BUDGETS, mode="global",
                                            strategy="random", rng=np.random.default_rng(t))
        random_op = identifiability_curve(g, BUDGETS, mode="operational",
                                          strategy="random", rng=np.random.default_rng(t))

        b_star_g_glob = budget_to_full_identifiability(g, mode="global")
        b_star_g_op = budget_to_full_identifiability(g, mode="operational")
        # random equivalent: sample B up to 2*K and find first hit
        def _random_b_star(mode):
            for B in range(0, 2 * K + 1):
                r = identifiability_curve(g, [B], mode=mode, strategy="random",
                                          rng=np.random.default_rng(t))[0]
                if r["identifiable"] == r["live"]:
                    return B
            return 2 * K
        b_star_r_glob = _random_b_star("global")
        b_star_r_op = _random_b_star("operational")

        per_trial.append({
            "trial": t, "live": live, "i0_global": i0_g, "i0_operational": i0_o,
            "greedy_global": greedy_glob, "greedy_operational": greedy_op,
            "random_global": random_glob, "random_operational": random_op,
            "b_star_greedy_global": b_star_g_glob,
            "b_star_random_global": b_star_r_glob,
            "b_star_greedy_operational": b_star_g_op,
            "b_star_random_operational": b_star_r_op,
        })
        print(f"{t:>5d} {live:>5d} {i0_g:>5d} {i0_o:>5d} "
              f"{b_star_g_glob:>8d} {b_star_r_glob:>8d} "
              f"{b_star_g_op:>7d} {b_star_r_op:>7d}")

    # aggregate: per-B mean identifiable_fraction and sign-test greedy vs random
    agg = {"global": [], "operational": []}
    for mode in ("global", "operational"):
        for i, B in enumerate(BUDGETS):
            g_vals = [row[f"greedy_{mode}"][i]["identifiable_fraction"] for row in per_trial]
            r_vals = [row[f"random_{mode}"][i]["identifiable_fraction"] for row in per_trial]
            deltas = [gv - rv for gv, rv in zip(g_vals, r_vals)]
            wins, ties, losses = _paired_sign_test(deltas)
            agg[mode].append({
                "B": B,
                "greedy_mean": float(np.mean(g_vals)),
                "greedy_std": float(np.std(g_vals)),
                "random_mean": float(np.mean(r_vals)),
                "random_std": float(np.std(r_vals)),
                "delta_mean": float(np.mean(deltas)),
                "delta_ci95_lo": float(np.mean(deltas) - 1.96 * np.std(deltas) / np.sqrt(max(1, len(deltas)))),
                "delta_ci95_hi": float(np.mean(deltas) + 1.96 * np.std(deltas) / np.sqrt(max(1, len(deltas)))),
                "wins": wins, "ties": ties, "losses": losses,
            })

    b_star_g_glob_vals = [r["b_star_greedy_global"] for r in per_trial]
    b_star_r_glob_vals = [r["b_star_random_global"] for r in per_trial]
    b_star_g_op_vals = [r["b_star_greedy_operational"] for r in per_trial]
    b_star_r_op_vals = [r["b_star_random_operational"] for r in per_trial]
    live_vals = [r["live"] for r in per_trial]
    i0g_vals = [r["i0_global"] for r in per_trial]
    i0o_vals = [r["i0_operational"] for r in per_trial]

    summary = {
        "n_trials": len(per_trial),
        "K": K, "n": n, "data_source": data_source,
        "live_mean": float(np.mean(live_vals)),
        "i0_global_mean": float(np.mean(i0g_vals)),
        "i0_operational_mean": float(np.mean(i0o_vals)),
        "i0_global_fraction_mean": float(np.mean([g / l for g, l in zip(i0g_vals, live_vals)])),
        "i0_operational_fraction_mean": float(np.mean([o / l for o, l in zip(i0o_vals, live_vals)])),
        "b_star_greedy_global_median": float(np.median(b_star_g_glob_vals)),
        "b_star_random_global_median": float(np.median(b_star_r_glob_vals)),
        "b_star_greedy_operational_median": float(np.median(b_star_g_op_vals)),
        "b_star_random_operational_median": float(np.median(b_star_r_op_vals)),
        "b_star_random_over_greedy_global": float(
            np.median(b_star_r_glob_vals) / max(1e-9, np.median(b_star_g_glob_vals))),
        "b_star_random_over_greedy_operational": float(
            np.median(b_star_r_op_vals) / max(1e-9, np.median(b_star_g_op_vals))),
        "budgets": BUDGETS,
        "aggregate": agg,
        "per_trial": per_trial,
    }

    print("\naggregate curves (identifiable-fraction, greedy vs random):")
    for mode in ("global", "operational"):
        print(f"  [{mode}]")
        print(f"    {'B':>3}  {'greedy':>8}  {'random':>8}  {'Δ':>7}  "
              f"{'CI95_lo':>7}  {'wins':>4}/{'losses':<4}")
        for row in agg[mode]:
            print(f"    {row['B']:>3d}  {row['greedy_mean']:>8.3f}  {row['random_mean']:>8.3f}  "
                  f"{row['delta_mean']:>+7.3f}  {row['delta_ci95_lo']:>+7.3f}  "
                  f"{row['wins']:>4d}/{row['losses']:<4d}")
    print(f"\n  median B* (greedy global): {summary['b_star_greedy_global_median']:.1f}, "
          f"random global: {summary['b_star_random_global_median']:.1f} "
          f"(random is {summary['b_star_random_over_greedy_global']:.2f}× worse)")
    print(f"  median B* (greedy op):     {summary['b_star_greedy_operational_median']:.1f}, "
          f"random op: {summary['b_star_random_operational_median']:.1f} "
          f"(random is {summary['b_star_random_over_greedy_operational']:.2f}× worse)")
    return summary


def save_plot(summary):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:  # pragma: no cover
        print(f"[plot skipped: {e}]"); return

    fig, axes = plt.subplots(1, 2, figsize=(12.5, 4.5), constrained_layout=True)
    for ax, mode in zip(axes, ("global", "operational")):
        rows = summary["aggregate"][mode]
        Bs = [r["B"] for r in rows]
        gm = [r["greedy_mean"] for r in rows]
        gs = [r["greedy_std"] for r in rows]
        rm = [r["random_mean"] for r in rows]
        rs = [r["random_std"] for r in rows]
        ax.errorbar(Bs, gm, yerr=gs, fmt="o-", color="#1976d2", lw=2, capsize=3,
                    label="greedy (dominance-aware)")
        ax.errorbar(Bs, rm, yerr=rs, fmt="s--", color="#e53935", lw=2, capsize=3,
                    label="random singleton")
        ax.axhline(1.0, ls=":", color="#666", lw=0.8)
        i0_key = "i0_global_fraction_mean" if mode == "global" else "i0_operational_fraction_mean"
        ax.axhline(summary[i0_key], ls="-.", color="#333", lw=0.8,
                   label=f"baseline (B=0) = {summary[i0_key]:.2f}")
        ax.set_xlabel("canary budget B")
        ax.set_ylabel("identifiable fraction")
        title = f"{mode.capitalize()} identifiability vs canary budget"
        if mode == "global":
            title += (f"\nK={summary['K']}, n={summary['n']}, "
                      f"median B* greedy={summary['b_star_greedy_global_median']:.0f}, "
                      f"random={summary['b_star_random_global_median']:.0f}")
        else:
            title += (f"\nmedian B* greedy={summary['b_star_greedy_operational_median']:.0f}, "
                      f"random={summary['b_star_random_operational_median']:.0f}")
        ax.set_title(title)
        ax.set_ylim(0.0, 1.05)
        ax.legend(frameon=False, fontsize=9, loc="lower right")
        ax.grid(alpha=0.3)

    fig.savefig("results/diversity.png", dpi=140, bbox_inches="tight")
    print("[saved -> results/diversity.png]")


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    K = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 400
    use_real = "--synth" not in sys.argv
    os.makedirs("results", exist_ok=True)
    summary = run(trials=trials, K=K, n=n, use_real=use_real)
    with open("results/diversity.json", "w") as f:
        json.dump(summary, f, indent=2)
    save_plot(summary)


if __name__ == "__main__":
    main()
