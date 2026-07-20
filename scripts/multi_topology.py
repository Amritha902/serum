#!/usr/bin/env python
"""Does the content-aware flagship generalize beyond email-Eu-core?

The original flagship (results/real/email_topo.json) ran the SERUM policy
lineup on the SNAP email-Eu-core topology (~1k nodes, real org departments).
This script repeats the identical paired comparison on the SNAP
Autonomous-Systems Internet graph (~6.4k nodes, sparse power-law) so we can
report whether the win of content-aware over the best structural baseline
survives on a second real topology. Every trial pairs identical outbreaks
across policies (same graph, same payload, same seeds, same coin flips), so
per-topology deltas are unbiased.

Output: ``results/real/snap_topologies.json`` — the per-policy stats and
paired-report for each SNAP topology, alongside the shared trial spec.

Usage:
    python scripts/multi_topology.py               # both topologies, n=20
    python scripts/multi_topology.py --trials 10   # cheaper run
    python scripts/multi_topology.py --topologies email
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from serum.experiments.harness import (  # noqa: E402
    TrialSpec, compare_policies, paired_report,
)


DEFAULT_TOPOLOGIES = ("email", "as")


def build_spec(topology: str, budget: int = 3, horizon: int = 60, n_cves: int = 30,
               homophily: float = 0.4, band=(0.30, 0.80), n_segments: int = 30) -> TrialSpec:
    """Shared spec across topologies so per-topology deltas are comparable.

    Tightened budget + higher-prevalence band from the run_experiment defaults so
    every topology sees a non-trivial outbreak (the AS graph is sparse enough
    that a loose defence-vs-worm regime saturates all policies at zero infected).
    """
    return TrialSpec(
        topology=topology, n_cves=n_cves, homophily=homophily,
        budget_per_step=budget, horizon=horizon, beta=0.35,
        payload_strategy="band", prev_band=tuple(band),
        n_seeds=3, n_segments=n_segments,
    )


def run_topology(topology: str, records, trials: int, base_seed: int = 0,
                 budget: int = 3, horizon: int = 60) -> dict:
    """One topology, ``trials`` paired outbreaks, returns per-policy stats +
    paired report + spec + wall time."""
    spec = build_spec(topology, budget=budget, horizon=horizon)
    t0 = time.monotonic()
    stats, _ = compare_policies(spec, n_trials=trials, base_seed=base_seed,
                                verbose=False, records=records)
    seconds = time.monotonic() - t0
    return {
        "topology": topology,
        "trials": trials,
        "seconds": round(seconds, 2),
        "spec": vars(spec),
        "policies": {name: s.summary() for name, s in stats.items()},
        "paired_report": paired_report(stats),
    }


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trials", type=int, default=20)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--topologies", nargs="+", default=list(DEFAULT_TOPOLOGIES),
                    help="which SNAP topologies to run ('email', 'as')")
    ap.add_argument("--budget", type=int, default=3,
                    help="isolations per step (kept tight so the AS graph doesn't"
                         " saturate every policy at zero)")
    ap.add_argument("--horizon", type=int, default=60)
    ap.add_argument("--outdir", default=os.path.join("results", "real"))
    ap.add_argument("--out", default="snap_topologies.json")
    return ap.parse_args(argv)


def _fmt_paired(rep: dict, kind: str) -> str:
    r = rep[kind]
    lo, hi = r["ci95_abs"]
    return (f"vs {r['vs']:<18} Δ={100*r['mean_abs_reduction']:+.2f}pp "
            f"(CI95 [{100*lo:+.2f}, {100*hi:+.2f}]) "
            f"p={r['p_value']:.2e}  wins {r['wins']}/{rep['n_trials']}")


def print_report(res: dict) -> None:
    print(f"\n=== {res['topology']} (n={res['trials']}, {res['seconds']:.1f}s) ===")
    order = ["no-defense", "random", "acquaintance", "degree", "eigenvector",
             "betweenness", "greedy-blocking", "oracle-delay-5", "content-aware",
             "content-aware-oracle"]
    for name in order:
        if name not in res["policies"]:
            continue
        s = res["policies"][name]
        inf_m, inf_s = s["infected_fraction"]
        av_m, _ = s["availability"]
        print(f"  {name:<24} infected={100*inf_m:6.2f}±{100*inf_s:4.1f}%  "
              f"avail={100*av_m:5.1f}%")
    rep = res["paired_report"]
    if rep is not None:
        print(f"  PRIMARY:  {_fmt_paired(rep, 'primary')}")
        print(f"  ENSEMBLE: {_fmt_paired(rep, 'ensemble')}")


def main(argv=None) -> int:
    args = parse_args(argv)
    from serum.data.clean import load_clean_csv  # deferred: skips if data missing
    csv_path = "data/clean/cves.csv"
    if not os.path.exists(csv_path):
        print(f"[multi_topology] missing {csv_path}; run scripts/ingest_nvd.py first",
              file=sys.stderr)
        return 2
    records = load_clean_csv(csv_path)
    print(f"[multi_topology] {len(records)} cleaned CVEs")

    results = []
    for topo in args.topologies:
        if topo not in ("email", "as"):
            print(f"[multi_topology] unknown SNAP topology {topo!r}; skipping",
                  file=sys.stderr)
            continue
        print(f"[multi_topology] running {topo} ({args.trials} paired trials)...",
              flush=True)
        res = run_topology(topo, records, trials=args.trials, base_seed=args.seed,
                           budget=args.budget, horizon=args.horizon)
        results.append(res)
        print_report(res)

    os.makedirs(args.outdir, exist_ok=True)
    out_path = os.path.join(args.outdir, args.out)
    payload = {"topologies": {r["topology"]: r for r in results}}
    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\n[multi_topology] saved -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
