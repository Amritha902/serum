#!/usr/bin/env python
"""Blast radius & cost-weighted availability: steer content-aware defence toward
high-value hosts.

Real fleets are lopsided: a handful of hosts (crown-jewel databases, domain
controllers, payment gateways) matter far more than the rest. Fraction infected
is not the right objective in this regime -- what matters is *how much value*
the outbreak lands on (blast radius) and *how much operational cost* the
defender pays isolating hosts. This script attaches heavy-tailed criticality to
every host and asks: with the same budget, can our content-aware agent be
steered by that criticality to protect the value that matters?

Policies compared per trial:
  * no-defense           (lower bound)
  * degree               (payload-blind structural)
  * content-aware        (value-blind: our default)
  * content-aware+value  (value-weighted: our steering variant)

Metrics per policy (paired across the same graph + payload + criticality):
  * infected_fraction    (unweighted outbreak size)
  * blast_radius         (fraction of TOTAL value ever infected)
  * availability         (fraction of hosts never isolated)
  * cost_availability    (fraction of TOTAL isolation cost preserved)

Honest expectation: value-weighted should reduce blast_radius vs value-blind,
at possibly no gain (or a small loss) on plain infected_fraction. That trade is
exactly the point -- protection is now steerable.

Saves results/blast_radius.json.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402

from serum.agents.content_aware import ContentAwareAgent  # noqa: E402
from serum.baselines.heuristics import DegreeDefense, NoDefense  # noqa: E402
from serum.data.clean import load_clean_csv  # noqa: E402
from serum.experiments.harness import TrialSpec, build_episode  # noqa: E402
from serum.sim.network import assign_criticality  # noqa: E402


POLICIES = {
    "no-defense": lambda g: NoDefense(),
    "degree": lambda g: DegreeDefense(),
    "content-aware": lambda g: ContentAwareAgent(g, value_weighted=False),
    "content-aware+value": lambda g: ContentAwareAgent(g, value_weighted=True),
}


def run_one_trial(spec, records, seed, alpha=1.2, value_max=100.0):
    """Run every policy against ONE outbreak (shared graph + payload +
    criticality + spread RNG). Returns a per-policy dict of metrics."""
    factory, _ = build_episode(spec, seed, records=records)
    # Attach heavy-tailed criticality to the shared base graph; every subsequent
    # factory() copy inherits it, so all policies see the SAME value/cost per
    # host on this trial (paired design).
    env0 = factory()
    crit_rng = np.random.default_rng(seed + 42_000_001)
    assign_criticality(env0.g0, alpha=alpha, value_max=value_max,
                       cost_scales_with_value=True, rng=crit_rng)

    out = {}
    for name, make in POLICIES.items():
        env = factory()
        res = env.run(make(env.g))
        out[name] = {
            "infected_fraction": res.infected_fraction,
            "blast_radius": res.blast_radius,
            "availability": res.availability,
            "cost_availability": res.cost_availability,
        }
    return out


def summarize(rows):
    """Aggregate per-policy means and standard errors across trials."""
    policies = list(rows[0].keys())
    metrics = list(rows[0][policies[0]].keys())
    summary = {}
    for p in policies:
        summary[p] = {}
        for m in metrics:
            xs = np.array([r[p][m] for r in rows], dtype=float)
            summary[p][m] = {
                "mean": float(xs.mean()),
                "se": float(xs.std(ddof=1) / np.sqrt(len(xs))) if len(xs) > 1 else 0.0,
            }
    return summary


def paired_delta(rows, policy_a: str, policy_b: str, metric: str):
    """Paired mean difference (a - b) with a bootstrap 95% CI."""
    a = np.array([r[policy_a][metric] for r in rows], dtype=float)
    b = np.array([r[policy_b][metric] for r in rows], dtype=float)
    diff = a - b
    rng = np.random.default_rng(0)
    idx = np.arange(len(diff))
    boots = np.array([
        diff[rng.choice(idx, size=len(idx), replace=True)].mean()
        for _ in range(2000)
    ])
    lo, hi = np.percentile(boots, [2.5, 97.5])
    return {
        "mean": float(diff.mean()),
        "ci95": (float(lo), float(hi)),
        "wins": int((diff < 0).sum()),  # wins = a smaller than b (fewer bad things)
    }


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    records = load_clean_csv("data/clean/cves.csv")
    # Constrained regime: enough seeds and low enough budget that meaningful
    # outbreaks land, so blast radius has room to differ across policies.
    spec = TrialSpec(
        n=500, n_cves=40, homophily=0.4,
        payload_strategy="band", prev_band=(0.15, 0.55),
        n_seeds=10, budget_per_step=2, horizon=25,
    )

    print(f"[running {trials} paired trials, alpha=1.2, value_max=100]")
    rows = []
    for s in range(trials):
        rows.append(run_one_trial(spec, records, seed=s))
        if (s + 1) % 5 == 0:
            print(f"  trial {s + 1}/{trials} done", flush=True)

    summary = summarize(rows)

    # Print per-policy means (blast_radius is what we care about most).
    print()
    header = f"{'policy':>22} {'inf%':>7} {'blast%':>7} {'avail%':>7} {'cost_av%':>9}"
    print(header)
    print("-" * len(header))
    for p in ["no-defense", "degree", "content-aware", "content-aware+value"]:
        s = summary[p]
        print(f"{p:>22} "
              f"{100*s['infected_fraction']['mean']:>6.2f} "
              f"{100*s['blast_radius']['mean']:>6.2f} "
              f"{100*s['availability']['mean']:>6.2f} "
              f"{100*s['cost_availability']['mean']:>8.2f}")

    # Paired steering effect: content-aware+value vs content-aware, on blast.
    steer = paired_delta(rows, "content-aware+value", "content-aware",
                         "blast_radius")
    steer_inf = paired_delta(rows, "content-aware+value", "content-aware",
                             "infected_fraction")
    print()
    print("[paired] content-aware+value - content-aware (lower = better on blast)")
    print(f"  blast_radius delta:      mean={100*steer['mean']:+.2f}%  "
          f"ci95=({100*steer['ci95'][0]:+.2f}%, {100*steer['ci95'][1]:+.2f}%)  "
          f"wins={steer['wins']}/{len(rows)}")
    print(f"  infected_fraction delta: mean={100*steer_inf['mean']:+.2f}%  "
          f"ci95=({100*steer_inf['ci95'][0]:+.2f}%, {100*steer_inf['ci95'][1]:+.2f}%)  "
          f"wins={steer_inf['wins']}/{len(rows)}")

    os.makedirs("results", exist_ok=True)
    with open("results/blast_radius.json", "w") as f:
        json.dump({
            "spec": {
                "n": spec.n, "n_cves": spec.n_cves,
                "homophily": spec.homophily, "band": spec.prev_band,
                "trials": trials, "criticality_alpha": 1.2,
                "value_max": 100.0,
            },
            "summary": summary,
            "paired_steer_blast": steer,
            "paired_steer_infected": steer_inf,
            "rows": rows,
        }, f, indent=2)
    print("\n[saved -> results/blast_radius.json]")


if __name__ == "__main__":
    main()
