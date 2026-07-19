#!/usr/bin/env python
"""Spread-anonymity duality: can a worm both spread widely and stay anonymous?

Theorem (docs/THEORY.md): the number of confusers of exploit c is at most
N(S(c)/n) - 1, where S(c) is its reachable vulnerable-component size and N(pi) is
the number of CVEs with prevalence >= pi. Since N is non-increasing, more spread
=> weakly fewer possible confusers. This script (1) verifies the bound holds for
every CVE (it must -- it's a theorem), and (2) measures whether real exploits
*actually* trace a downward-sloping spread-vs-anonymity frontier, and the
spread-anonymity correlation. (2) is the empirical question that matters.

Saves results/duality.json and results/duality.png.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402

from serum.data.clean import load_clean_csv  # noqa: E402
from serum.data.profiles import generate_real_network  # noqa: E402
from serum.inference.identifiability import duality_table  # noqa: E402


def main():
    nets = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    records = load_clean_csv("data/clean/cves.csv")
    all_rows = []
    violations = 0
    for t in range(nets):
        g = generate_real_network(records, n=500, n_cves=40, n_products=80,
                                  homophily=0.4, rng=np.random.default_rng(t))
        rows = duality_table(g)
        violations += sum(1 for r in rows if not r["satisfies_bound"])
        all_rows.extend(rows)

    spread = np.array([r["spread_frac"] for r in all_rows])
    anon = np.array([r["anonymity"] for r in all_rows])
    # correlation between spread and anonymity (duality => negative)
    if spread.std() > 0 and anon.std() > 0:
        corr = float(np.corrcoef(spread, anon)[0, 1])
    else:
        corr = float("nan")

    # empirical Pareto frontier: max anonymity achieved in each spread bin
    bins = np.linspace(0, spread.max() + 1e-9, 9)
    frontier = []
    for lo, hi in zip(bins[:-1], bins[1:]):
        m = (spread >= lo) & (spread < hi)
        if m.any():
            frontier.append((float((lo + hi) / 2), int(anon[m].max()),
                             float(anon[m].mean())))

    print(f"CVEs analysed: {len(all_rows)} over {nets} networks")
    print(f"bound violations (must be 0): {violations}")
    print(f"spread-anonymity correlation: {corr:+.3f}  "
          f"({'downward-sloping (duality holds empirically)' if corr < -0.1 else 'weak/flat -- duality is only the bound, not realised'})")
    print(f"\n{'spread-frac':>12} {'max-anonymity':>14} {'mean-anonymity':>15}")
    for s, mx, mn in frontier:
        print(f"{s:>12.2f} {mx:>14} {mn:>15.2f}")

    os.makedirs("results", exist_ok=True)
    json.dump({"n_cves": len(all_rows), "violations": violations,
               "correlation": corr, "frontier": frontier},
              open("results/duality.json", "w"), indent=2)
    save_plot(spread, anon, all_rows)


def save_plot(spread, anon, rows):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:  # pragma: no cover
        print(f"[plot skipped: {e}]"); return
    plt.figure(figsize=(7.5, 5))
    plt.scatter(100 * spread, anon, s=14, alpha=0.35, c="#5c6bc0",
                edgecolors="none", label="exploits (per CVE)")
    # bound curve: max anonymity = N(s)-1, sorted by spread
    sr = sorted(rows, key=lambda r: r["spread_frac"])
    plt.plot([100 * r["spread_frac"] for r in sr], [r["bound"] for r in sr],
             c="#e53935", lw=2, label="duality bound  N(S/n) − 1")
    plt.xlabel("spread reach (% of fleet)  → wider")
    plt.ylabel("anonymity (# confusers)  → more hidden")
    plt.title("Spread–anonymity duality: a worm cannot both spread and hide\n"
              "(no exploit exceeds the red bound; the achievable region shrinks with spread)")
    plt.legend(frameon=False, fontsize=9)
    plt.tight_layout()
    plt.savefig("results/duality.png", dpi=140)
    print("[saved -> results/duality.png, results/duality.json]")


if __name__ == "__main__":
    main()
