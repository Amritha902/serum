#!/usr/bin/env python
"""Turn results/sweep.jsonl into the 'when does content-awareness help?' analysis.

Reads the parameter sweep and reports, per configuration, how much the
content-aware agent reduces infection relative to the *best* structure-only
baseline. Prints a ranked table and saves a phase-diagram figure
(results/phase_diagram.png): infection-reduction heatmaps over spread-rate x
budget, faceted by topology and attacker strategy.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SWEEP = "results/sweep.jsonl"


def load(path):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def edge(rec):
    """Relative infection reduction of content-aware vs best structure-only."""
    pol = rec["policies"]
    ca = pol["content-aware"]["infected_fraction"][0]
    struct = [pol[n]["infected_fraction"][0] for n in ("degree", "betweenness") if n in pol]
    best = min(struct) if struct else 1.0
    return (1.0 - ca / best) if best > 0 else 0.0, ca, best


def main():
    if not os.path.exists(SWEEP):
        print(f"no sweep file at {SWEEP}; run scripts/sweep.py first")
        return
    rows = load(SWEEP)
    print(f"loaded {len(rows)} configurations\n")

    scored = []
    for r in rows:
        e, ca, best = edge(r)
        c = r["_config"]
        scored.append((e, ca, best, c))
    scored.sort(key=lambda x: x[0], reverse=True)

    print(f"{'edge':>7}  {'CA inf%':>8}  {'best-struct%':>12}   config")
    print("-" * 72)
    for e, ca, best, c in scored:
        tag = f"topo={c['topology']:<3} beta={c['beta']:<4} " \
              f"{c['payload_strategy']:<8} budget={c['budget_per_step']}"
        print(f"{e:>+6.1%}  {100*ca:>7.1f}  {100*best:>11.1f}    {tag}")

    edges = [e for e, *_ in scored]
    wins = sum(1 for e in edges if e > 0)
    print("-" * 72)
    print(f"content-aware beats best structure-only in {wins}/{len(edges)} configs; "
          f"mean edge = {sum(edges)/len(edges):+.1%}")

    save_phase_diagram(rows)


def save_phase_diagram(rows):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except Exception as ex:  # pragma: no cover
        print(f"[phase diagram skipped: {ex}]")
        return

    topos = sorted({r["_config"]["topology"] for r in rows})
    strats = sorted({r["_config"]["payload_strategy"] for r in rows})
    betas = sorted({r["_config"]["beta"] for r in rows})
    budgets = sorted({r["_config"]["budget_per_step"] for r in rows})

    lut = {}
    for r in rows:
        c = r["_config"]
        e, *_ = edge(r)
        lut[(c["topology"], c["payload_strategy"], c["beta"], c["budget_per_step"])] = e

    nrows, ncols = len(topos), len(strats)
    fig, axes = plt.subplots(nrows, ncols, figsize=(3.4 * ncols, 3.0 * nrows),
                             squeeze=False)
    vmax = max(abs(e) for e in lut.values()) or 1.0
    for i, topo in enumerate(topos):
        for j, strat in enumerate(strats):
            ax = axes[i][j]
            grid = np.full((len(budgets), len(betas)), np.nan)
            for bi, bud in enumerate(budgets):
                for ci, bet in enumerate(betas):
                    v = lut.get((topo, strat, bet, bud))
                    if v is not None:
                        grid[bi, ci] = 100 * v
            im = ax.imshow(grid, cmap="RdYlGn", vmin=-100 * vmax, vmax=100 * vmax,
                           aspect="auto", origin="lower")
            ax.set_xticks(range(len(betas)), [f"{b:g}" for b in betas])
            ax.set_yticks(range(len(budgets)), [str(b) for b in budgets])
            ax.set_title(f"{topo} · {strat}", fontsize=10)
            if i == nrows - 1:
                ax.set_xlabel("spread rate β")
            if j == 0:
                ax.set_ylabel("budget/step")
            for bi in range(len(budgets)):
                for ci in range(len(betas)):
                    if not np.isnan(grid[bi, ci]):
                        ax.text(ci, bi, f"{grid[bi, ci]:.0f}", ha="center",
                                va="center", fontsize=8, color="black")
    fig.suptitle("When does content-awareness help? "
                 "(% infection reduction vs best structure-only)", fontsize=12)
    cbar = fig.colorbar(im, ax=axes, shrink=0.6)
    cbar.set_label("infection reduction (%)")
    path = "results/phase_diagram.png"
    fig.savefig(path, dpi=140, bbox_inches="tight")
    print(f"[saved phase diagram -> {path}]")


if __name__ == "__main__":
    main()
