#!/usr/bin/env python
"""Validate SERUM on a MEASURED host-level inventory (the L1 experiment).

This is the experiment L1 asks for, wired end-to-end and gated only on data:
give it a real scan (host->CVE findings) and a real topology (edge list), and it
runs the flagship policy lineup on that network -- with the host->CVE mapping
taken verbatim from the scan (measured, not modeled) -- and reports whether the
content-aware agent beats the best structure-only baseline.

    python scripts/validate_real_inventory.py --scan scan.csv --edges edges.csv

scan.csv : long-format findings, columns (host, cve) [+ others ignored].
edges.csv: topology, one "host_a,host_b" per line.

With no --scan/--edges it runs a SELF-TEST on a synthetic fixture (clearly NOT
real data) purely to prove the pipeline works; that mode does not write results.
On real data it writes results/real_inventory.json.

Honest scope: the numbers this prints are only as real as the inventory you feed
it. On the synthetic self-test they mean nothing except "the pipeline runs."
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402
from scipy import stats as ss  # noqa: E402

from serum.agents.content_aware import ContentAwareAgent, OracleContentAware  # noqa: E402
from serum.baselines.heuristics import (BetweennessDefense, DegreeDefense,  # noqa: E402
                                        NoDefense)
from serum.data.real_inventory import build_inventory_network, load_scan_network  # noqa: E402
from serum.sim.environment import ContainmentEnv  # noqa: E402
from serum.sim.payload import sample_payload  # noqa: E402


def _synthetic_fixture(n=300, n_cves=25, seed=0):
    """A synthetic (host, cve) scan + edge list -- a FORMAT demo, NOT real data.
    Builds segmented zones so the pipeline exercises a realistic-shaped graph."""
    rng = np.random.default_rng(seed)
    import networkx as nx
    g0 = nx.barabasi_albert_graph(n, 3, seed=seed)
    seg = {v: v % 12 for v in g0.nodes()}
    seg_cves = {s: rng.choice(n_cves, size=6, replace=False) for s in set(seg.values())}
    scan = []
    for v in g0.nodes():
        k = int(max(1, rng.poisson(4)))
        pool = seg_cves[seg[v]]
        for c in rng.choice(pool, size=min(k, len(pool)), replace=False):
            scan.append((f"h{v}", f"CVE-SYN-{int(c):04d}"))
    edges = [(f"h{a}", f"h{b}") for a, b in g0.edges()]
    return scan, edges


def run(g, trials, budget, horizon, band):
    policies = {
        "no-defense": lambda: NoDefense(),
        "degree": lambda: DegreeDefense(),
        "betweenness": lambda: BetweennessDefense(),
        "content-aware": lambda: ContentAwareAgent(g),
        "content-aware-oracle": lambda: OracleContentAware(),
    }
    inf = {k: [] for k in policies}
    for s in range(trials):
        gen = np.random.default_rng(s + 12345)
        payload = sample_payload(g, beta=0.35, strategy="band", band=band, rng=gen)
        carriers = [v for v in g.nodes() if payload.cve in g.nodes[v]["vuln"]]
        if len(carriers) < 3:
            continue
        seeds = [str(x) for x in gen.choice(carriers, size=3, replace=False)]
        for name, mk in policies.items():
            dyn = np.random.default_rng(s + 777)      # shared coin-flips -> paired
            env = ContainmentEnv(g=g, payload=payload, seeds=seeds,
                                 budget_per_step=budget, horizon=horizon, rng=dyn)
            inf[name].append(env.run(mk()).infected_fraction)
    return {k: np.array(v, dtype=float) for k, v in inf.items()}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan", help="scan CSV (host, cve findings)")
    ap.add_argument("--edges", help="topology edge list (host_a,host_b)")
    ap.add_argument("--trials", type=int, default=40)
    ap.add_argument("--budget", type=int, default=8)
    ap.add_argument("--horizon", type=int, default=60)
    ap.add_argument("--band", type=float, nargs=2, default=(0.15, 0.55))
    args = ap.parse_args(argv)

    self_test = not (args.scan and args.edges)
    if self_test:
        print("[validate_real_inventory] SELF-TEST on a synthetic fixture "
              "(NOT real data; proves the pipeline runs).")
        scan, edges = _synthetic_fixture()
        g = build_inventory_network(scan, edges)
    else:
        g = load_scan_network(args.scan, args.edges)

    n_meas = sum(1 for v in g.nodes() if g.nodes[v]["vuln"])
    print(f"loaded network: {g.number_of_nodes()} hosts, {g.number_of_edges()} edges, "
          f"{g.graph['n_cves']} distinct CVEs, {n_meas} hosts with >=1 measured vuln")

    inf = run(g, args.trials, args.budget, args.horizon, tuple(args.band))
    best_struct = min(("degree", "betweenness"), key=lambda k: inf[k].mean())
    ca, bs = inf["content-aware"], inf[best_struct]
    gap = float(bs.mean() - ca.mean())
    wins = int((ca < bs).sum())
    try:
        _, p = ss.wilcoxon(ca, bs)
    except ValueError:
        p = 1.0

    print(f"\n{'policy':>22} {'infected%':>10}")
    print("-" * 34)
    for k in inf:
        print(f"{k:>22} {100 * inf[k].mean():>9.2f}")
    print(f"\ncontent-aware vs best structural ({best_struct}): "
          f"{100 * gap:+.2f}pp, wins {wins}/{len(ca)}, Wilcoxon p={p:.2e}")

    if self_test:
        print("\n[self-test complete; no results written. Provide --scan/--edges "
              "with a real inventory to run the L1 validation for real.]")
        return 0

    summary = {
        "n_hosts": g.number_of_nodes(), "n_edges": g.number_of_edges(),
        "n_cves": g.graph["n_cves"], "trials": args.trials, "budget": args.budget,
        "means_infected": {k: float(v.mean()) for k, v in inf.items()},
        "content_aware_vs_best_structural": {
            "best_structural": best_struct, "abs_reduction": gap,
            "wins_of_n": f"{wins}/{len(ca)}", "paired_wilcoxon_p": float(p)},
        "data_source": "measured-scan",
    }
    os.makedirs("results", exist_ok=True)
    json.dump(summary, open("results/real_inventory.json", "w"), indent=2)
    print("\n[saved -> results/real_inventory.json]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
