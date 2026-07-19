#!/usr/bin/env python
"""Overnight robustness sweep -- built to run for hours on the M5.

Walks a grid of topologies x spread rates x attacker strategies x budgets and,
for each cell, runs the full policy lineup over many paired outbreaks. Appends
one JSON record per cell to ``results/sweep.jsonl`` so progress survives
interruption and can be analysed incrementally. Designed for a "keep it running
all night" loop: re-running resumes by skipping cells already in the log.

Example (all night):
    python scripts/sweep.py --trials 40
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argus.experiments.harness import TrialSpec, compare_policies  # noqa: E402

GRID = {
    "topology": ["ba", "ws", "rgg"],
    "beta": [0.10, 0.15, 0.22],
    "payload_strategy": ["stealth", "popular"],
    "budget_per_step": [3, 5, 8],
}


def cell_key(cfg):
    return "|".join(f"{k}={cfg[k]}" for k in sorted(cfg))


def load_done(path):
    done = set()
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                try:
                    done.add(json.loads(line)["_cell"])
                except Exception:
                    pass
    return done


def edge(stats):
    """Relative infection reduction of content-aware vs best structure-only."""
    ca = stats["content-aware"].summary()["infected_fraction"][0]
    best_struct = min(
        stats[n].summary()["infected_fraction"][0]
        for n in ("degree", "betweenness") if n in stats
    )
    if best_struct <= 0:
        return 0.0
    return round(1.0 - ca / best_struct, 3)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trials", type=int, default=30)
    ap.add_argument("--out", default="results/sweep.jsonl")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    done = load_done(args.out)
    keys = list(GRID.keys())
    combos = list(itertools.product(*(GRID[k] for k in keys)))
    print(f"[sweep] {len(combos)} cells x {args.trials} trials "
          f"({len(done)} already done)")

    for i, values in enumerate(combos, 1):
        cfg = dict(zip(keys, values))
        key = cell_key(cfg)
        if key in done:
            print(f"[{i}/{len(combos)}] skip {key}")
            continue
        spec = TrialSpec(**cfg)
        t0 = time.perf_counter()
        stats, _ = compare_policies(spec, n_trials=args.trials,
                                    base_seed=args.seed, verbose=False)
        rec = {
            "_cell": key,
            "_config": cfg,
            "_edge_vs_structure": edge(stats),
            "_seconds": round(time.perf_counter() - t0, 1),
            "policies": {n: s.summary() for n, s in stats.items()},
        }
        with open(args.out, "a") as f:
            f.write(json.dumps(rec) + "\n")
        print(f"[{i}/{len(combos)}] {key}  edge={rec['_edge_vs_structure']:+.1%} "
              f"({rec['_seconds']}s)")

    print("[sweep] complete.")


if __name__ == "__main__":
    main()
