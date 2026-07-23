#!/usr/bin/env python
"""L4 — detection-noise channel: content-aware degrades faster than structure-only.

Question. Inventory noise (`scripts/inventory.py`) corrupts the defender's view
of each host's *vulnerabilities*. That is one sensor channel. A distinct one is
**infection-detection noise**: the defender's view of *who is currently infected*
is imperfect too. EDR sensors miss dwelling implants (false negatives); noisy
telemetry flags idle services as compromised (false positives). Both distort the
belief update AND the frontier the defender computes.

Design. Real NVD networks (n=400, K=30). For each (miss, false) point we run
`n_trials` paired trials at that noise level. On each trial we run four
policies through the identical outbreak:

  * ``NoDefense``  -- lower bound on outbreak size.
  * ``DegreeDefense`` -- payload-blind structural defender; needs an infected
    set to compute the frontier, so it feels missed detections but not false
    alarms as *belief poisoning* (structure has no belief to poison; it just
    defends around the observed spreaders).
  * ``ContentAwareAgent`` -- ours; feeds observed newly_infected into the CVE
    belief. Both channels hurt: false alarms poison the belief (a host that
    doesn't carry the true CVE now looks like evidence against it); missed
    detections withhold real evidence.
  * ``OracleContentAware`` -- upper bound on what any content-aware policy can
    do, unaffected by detection noise (it peeks at the true CVE).

Report. For each noise point we report mean infected fraction for each policy
plus the *paired* content-aware-minus-degree gap: positive means content-aware
wins, negative means it lost the sensor war to a payload-blind heuristic.

Honest expectation. Content-aware should degrade faster than degree; the
question is *how much* noise you can tolerate before content-awareness stops
paying off. We report the crossover point (if any) truthfully -- even if the
answer is that content-aware never wins in the tested grid.

Writes ``results/detection_noise.json``.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402
from scipy import stats as ss  # noqa: E402

from serum.agents.content_aware import ContentAwareAgent, OracleContentAware  # noqa: E402
from serum.baselines.heuristics import DegreeDefense, NoDefense  # noqa: E402
from serum.data.clean import load_clean_csv  # noqa: E402
from serum.experiments.harness import TrialSpec, build_episode  # noqa: E402


GRID = [
    (0.00, 0.00),
    (0.10, 0.00),
    (0.20, 0.00),
    (0.30, 0.00),
    (0.00, 0.02),
    (0.00, 0.05),
    (0.00, 0.10),
    (0.10, 0.02),
    (0.20, 0.05),
    (0.30, 0.10),
]


def _bootstrap_ci(x, n_boot=2000, seed=0):
    x = np.asarray(x, dtype=float)
    if len(x) == 0:
        return float("nan"), float("nan")
    rng = np.random.default_rng(seed)
    idx = np.arange(len(x))
    boots = np.array([x[rng.choice(idx, size=len(idx), replace=True)].mean()
                      for _ in range(n_boot)])
    lo, hi = np.percentile(boots, [2.5, 97.5])
    return float(lo), float(hi)


def _paired_p(a, b):
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)
    try:
        _, p = ss.wilcoxon(a, b)
    except ValueError:
        p = float("nan")
    return float(p)


def run(n_trials: int, n: int, K: int, budget: int, horizon: int):
    have_real = os.path.exists("data/clean/cves.csv")
    records = load_clean_csv("data/clean/cves.csv") if have_real else None
    data_source = "real" if records is not None else "synthetic"

    print(f"detection_noise: {n_trials} trials × {len(GRID)} noise points, "
          f"n={n}, K={K}, budget={budget}, horizon={horizon}, {data_source}")
    print(f"{'miss':>5} {'false':>6} {'no-def':>7} {'degree':>7} "
          f"{'CA':>7} {'oracle':>7} {'CA-Deg':>8} {'p':>9} {'wins':>5}/n")

    rows = []
    for miss, false in GRID:
        spec = TrialSpec(
            n=n, topology="ba", m=3, n_cves=K, n_seeds=3,
            budget_per_step=budget, horizon=horizon,
            homophily=0.4, beta=0.4, prev_band=(0.15, 0.55),
            detection_miss=miss, detection_false=false,
        )
        nd, de, ca, orc = [], [], [], []
        for t in range(n_trials):
            seed = 500_000 + int(miss * 1000) * 100 + int(false * 1000) + t * 7
            factory, _payload = build_episode(spec, seed, records=records)
            nd.append(factory().run(NoDefense()).infected_fraction)
            de.append(factory().run(DegreeDefense()).infected_fraction)
            env_ca = factory()
            ca.append(env_ca.run(ContentAwareAgent(env_ca.g)).infected_fraction)
            orc.append(factory().run(OracleContentAware(patch=True)).infected_fraction)
        nd_a = np.array(nd); de_a = np.array(de); ca_a = np.array(ca); orc_a = np.array(orc)
        gap = de_a - ca_a          # >0 = content-aware beats degree
        gap_lo, gap_hi = _bootstrap_ci(gap, seed=42 + int(miss * 1000) + int(false * 1000))
        p = _paired_p(ca_a, de_a)
        wins = int((gap > 0).sum())
        row = {
            "detection_miss": miss,
            "detection_false": false,
            "no_defense_mean": float(nd_a.mean()),
            "degree_mean": float(de_a.mean()),
            "content_aware_mean": float(ca_a.mean()),
            "oracle_mean": float(orc_a.mean()),
            "gap_ca_minus_deg_mean": float(gap.mean()),   # positive = CA better
            "gap_ci95": [gap_lo, gap_hi],
            "paired_wilcoxon_p": p,
            "wins": wins,
            "n_trials": n_trials,
            "per_trial": {
                "no_defense": nd, "degree": de,
                "content_aware": ca, "oracle": orc,
            },
        }
        rows.append(row)
        print(f"{miss:>5.2f} {false:>6.2f} {100 * row['no_defense_mean']:>6.1f}% "
              f"{100 * row['degree_mean']:>6.1f}% {100 * row['content_aware_mean']:>6.1f}% "
              f"{100 * row['oracle_mean']:>6.1f}% "
              f"{100 * row['gap_ca_minus_deg_mean']:>+7.2f}pp "
              f"{p:>9.1e} {wins:>2d}/{n_trials}")

    # Find crossover: largest noise level where CA still beats degree (positive gap).
    winners = [r for r in rows if r["gap_ca_minus_deg_mean"] > 0]
    losers = [r for r in rows if r["gap_ca_minus_deg_mean"] <= 0]
    crossover_note = None
    if losers:
        first = min(losers, key=lambda r: r["detection_miss"] + r["detection_false"])
        crossover_note = (
            f"first noise point where content-aware no longer beats degree: "
            f"miss={first['detection_miss']}, false={first['detection_false']} "
            f"(gap={first['gap_ca_minus_deg_mean']:+.4f})"
        )
    elif winners:
        crossover_note = "content-aware beat degree at every tested noise point"
    else:
        crossover_note = "content-aware never beat degree in the tested grid"

    summary = {
        "n_trials": n_trials,
        "n_hosts": n, "K": K, "budget": budget, "horizon": horizon,
        "data_source": data_source,
        "grid": rows,
        "crossover": crossover_note,
    }

    os.makedirs("results", exist_ok=True)
    with open("results/detection_noise.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n[saved -> results/detection_noise.json]  {crossover_note}")


def main():
    n_trials = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    run(n_trials=n_trials, n=400, K=30, budget=5, horizon=40)


if __name__ == "__main__":
    main()
