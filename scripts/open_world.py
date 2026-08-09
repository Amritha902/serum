#!/usr/bin/env python
"""Open-world containment: what happens when the exploit is not in your catalog.

Motivation. Every SERUM result so far lives in a **closed world**: the payload's
CVE is drawn from the same universe the defender's belief ranges over, so the
truth is always inside the posterior's support. That assumption is doing more
work than it looks. It is also exactly what a zero-day violates -- the defining
property of a zero-day is that the vulnerability is real and exploitable but
absent from the defender's catalog, scanner, and CMDB.

This script removes the assumption and measures what breaks.

Design. Real NVD-derived networks on a real SNAP topology. Each trial builds one
outbreak and replays it under two **catalog conditions**, paired on the same
seed so the graph, payload, seeds, and infection coin-flips are identical:

  * ``known``    -- the defender's catalog contains the payload's CVE (the
                    closed-world assumption every previous result makes).
  * ``zero-day`` -- the payload's CVE is withheld from the defender's view of
                    every host (``serum.sim.catalog.withhold_from_catalog``).
                    Ground truth and spread dynamics are untouched; only the
                    defender's knowledge changes.

Policies. ``NoDefense`` (upper bound on damage), ``DegreeDefense`` and
``GreedyBlockingDefense`` (payload-blind, and therefore *indifferent* to the
catalog condition -- they are the control), ``ContentAwareAgent`` (the flagship),
``RobustAgent`` (the existing belief-audit hedge, built for poisoning), and
``OpenWorldAgent`` (the calibrated misspecification monitor + never-idle rule).

What we are testing, stated as falsifiable predictions:

  H1. Under ``zero-day`` the content-aware agent loses its advantage and may fall
      *behind* payload-blind heuristics, because it spends budget on the wrong
      vulnerable subgraph -- or spends none at all.
  H2. The poisoning-era ``RobustAgent`` audit does **not** fully rescue it: its
      trust weight is driven by the MAP CVE's hit rate, and under a withheld CVE
      a spurious catalog CVE can still show a high hit rate by co-occurrence.
  H3. ``OpenWorldAgent`` detects the misspecification within a small number of
      infections and recovers to structure-only parity.
  H4. On ``known`` outbreaks the monitor's false-alarm rate is at or below
      ``alpha``, so open-world safety costs essentially nothing when the catalog
      is right. (This is the one that decides whether it is deployable.)

Every one of these can come out against us; the script reports whichever way it
lands. Writes ``results/open_world.json``.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402
from scipy import stats as ss  # noqa: E402

from serum.agents.content_aware import ContentAwareAgent  # noqa: E402
from serum.agents.openworld import OpenWorldAgent  # noqa: E402
from serum.agents.robust import RobustAgent  # noqa: E402
from serum.baselines.heuristics import (  # noqa: E402
    DegreeDefense,
    GreedyBlockingDefense,
    NoDefense,
)
from serum.data.clean import load_clean_csv  # noqa: E402
from serum.experiments.harness import TrialSpec, build_episode  # noqa: E402
from serum.sim.catalog import withhold_confusable  # noqa: E402

ALPHA = 0.01          # monitor significance level
MISS_FLOOR = 0.02     # assumed inventory miss rate under H0
MIN_EVIDENCE = 4      # never alarm on fewer than this many infections


def _make_policies(g):
    """Fresh policy instances bound to this trial's graph."""
    return [
        ("no-defense", NoDefense()),
        ("degree", DegreeDefense()),
        ("greedy-blocking", GreedyBlockingDefense()),
        ("content-aware", ContentAwareAgent(g)),
        ("robust", RobustAgent(g)),
        ("open-world", OpenWorldAgent(g, alpha=ALPHA, miss_floor=MISS_FLOOR,
                                      min_evidence=MIN_EVIDENCE)),
    ]


def _paired_p(a, b):
    a, b = np.asarray(a, float), np.asarray(b, float)
    if len(a) == 0 or np.allclose(a, b):
        return float("nan")
    try:
        return float(ss.wilcoxon(a, b).pvalue)
    except ValueError:
        return float("nan")


def _bootstrap_ci(x, n_boot=2000, seed=0):
    x = np.asarray(x, dtype=float)
    if len(x) == 0:
        return float("nan"), float("nan")
    rng = np.random.default_rng(seed)
    boots = np.array([rng.choice(x, size=len(x), replace=True).mean()
                      for _ in range(n_boot)])
    return tuple(float(v) for v in np.percentile(boots, [2.5, 97.5]))


def run_condition(spec, n_trials, base_seed, records, withhold: bool, j: int = 0):
    """Run every policy over ``n_trials`` paired outbreaks in one catalog condition.

    ``withhold=False`` is the closed world. ``withhold=True`` strips the payload's
    CVE from the defender's view, plus its ``j`` nearest carrier-set proxies.
    """
    infected = {}
    availability = {}
    alarms, alarm_at, residuals = [], [], []

    for t in range(n_trials):
        seed = base_seed + t
        # build_episode is deterministic in `seed`, so every condition gets the
        # identical network, payload, seed hosts, and infection coin-flips.
        factory, payload = build_episode(spec, seed, records=records)
        g = factory().g0
        if withhold:
            _, residual = withhold_confusable(g, payload.cve, j=j)
            residuals.append(residual)

        for name, policy in _make_policies(g):
            res = factory().run(policy)
            infected.setdefault(name, []).append(res.infected_fraction)
            availability.setdefault(name, []).append(res.availability)
            if name == "open-world":
                alarms.append(bool(policy.alarmed))
                if policy.alarmed:
                    alarm_at.append(int(policy.alarm_at))

    summary = {}
    for name, xs in infected.items():
        lo, hi = _bootstrap_ci(xs)
        summary[name] = {
            "infected_mean": round(float(np.mean(xs)), 5),
            "infected_ci95": [round(lo, 5), round(hi, 5)],
            "availability_mean": round(float(np.mean(availability[name])), 5),
        }
    return {
        "summary": summary,
        "raw_infected": infected,
        "residual_proxy_mean": (round(float(np.mean(residuals)), 4)
                                if residuals else None),
        "alarm_rate": round(float(np.mean(alarms)), 4) if alarms else None,
        "alarm_at_median": (float(np.median(alarm_at)) if alarm_at else None),
        "alarm_at_mean": (round(float(np.mean(alarm_at)), 2) if alarm_at else None),
    }


def main():
    n_trials = int(os.environ.get("SERUM_TRIALS", 40))
    have_real = os.path.exists("data/clean/cves.csv")
    records = load_clean_csv("data/clean/cves.csv") if have_real else None
    spec = TrialSpec(
        n=500, topology="email", n_cves=30, n_products=80,
        n_segments=12, homophily=0.6, budget_per_step=5, horizon=40,
        payload_strategy="band",
    )

    print(f"[open-world] real NVD records: {len(records) if records else 0}; "
          f"trials={n_trials}")

    # The sweep. j = how many carrier-set proxies are stripped along with the
    # payload's own CVE. j=0 is "one unknown CVE, catalog may still proxy it";
    # large j is "an entire uninventoried product", where nothing in the catalog
    # sits on the same machines.
    conditions = [("known", False, 0)] + [
        (f"zero_day_j{j}", True, j) for j in (0, 1, 2, 4, 8)
    ]

    out = {}
    for label, withhold, j in conditions:
        print(f"[open-world] condition = {label} ...")
        out[label] = run_condition(spec, n_trials, 0, records, withhold, j=j)
        rp = out[label]["residual_proxy_mean"]
        if rp is not None:
            print(f"    residual best-proxy Jaccard = {rp:.3f}")
        for name, s in out[label]["summary"].items():
            print(f"    {name:>16}  infected={s['infected_mean']:.4f}  "
                  f"avail={s['availability_mean']:.4f}")
        if out[label]["alarm_rate"] is not None:
            print(f"    monitor alarm rate = {out[label]['alarm_rate']:.3f}"
                  f"  median infections to alarm = {out[label]['alarm_at_median']}")

    # -- the comparisons that decide H1-H4 -------------------------------
    # The decisive condition is the *hardest* one: an unknown vulnerability with
    # no carrier-set proxy left in the catalog.
    hardest = f"zero_day_j{8}"
    zd = out[hardest]["raw_infected"]
    kn = out["known"]["raw_infected"]
    out_alarm = out[hardest]["alarm_rate"]
    tests = {
        # H1: does content-awareness survive an out-of-catalog exploit?
        "H1_zeroday_content_vs_greedy": {
            "content_aware": round(float(np.mean(zd["content-aware"])), 5),
            "greedy_blocking": round(float(np.mean(zd["greedy-blocking"])), 5),
            "p": _paired_p(zd["content-aware"], zd["greedy-blocking"]),
        },
        # H1b: how much of the closed-world win is an artefact of the assumption?
        "H1b_content_known_vs_zeroday": {
            "known": round(float(np.mean(kn["content-aware"])), 5),
            "zero_day": round(float(np.mean(zd["content-aware"])), 5),
            "p": _paired_p(kn["content-aware"], zd["content-aware"]),
        },
        # H2: does the poisoning-era audit rescue it?
        "H2_zeroday_robust_vs_greedy": {
            "robust": round(float(np.mean(zd["robust"])), 5),
            "greedy_blocking": round(float(np.mean(zd["greedy-blocking"])), 5),
            "p": _paired_p(zd["robust"], zd["greedy-blocking"]),
        },
        # H3: does the monitor recover the loss?
        "H3_zeroday_openworld_vs_content": {
            "open_world": round(float(np.mean(zd["open-world"])), 5),
            "content_aware": round(float(np.mean(zd["content-aware"])), 5),
            "p": _paired_p(zd["open-world"], zd["content-aware"]),
        },
        "H3b_zeroday_openworld_vs_greedy": {
            "open_world": round(float(np.mean(zd["open-world"])), 5),
            "greedy_blocking": round(float(np.mean(zd["greedy-blocking"])), 5),
            "p": _paired_p(zd["open-world"], zd["greedy-blocking"]),
            "alarm_rate": out_alarm,
        },
        # H4: what does open-world safety cost on well-specified outbreaks?
        "H4_known_openworld_vs_content": {
            "open_world": round(float(np.mean(kn["open-world"])), 5),
            "content_aware": round(float(np.mean(kn["content-aware"])), 5),
            "p": _paired_p(kn["open-world"], kn["content-aware"]),
            "false_alarm_rate": out["known"]["alarm_rate"],
            "alpha": ALPHA,
        },
    }

    for k, v in tests.items():
        print(f"\n[{k}] {json.dumps(v)}")

    # drop raw arrays from the artefact but keep them for reproducibility
    payload = {
        "config": {
            "n_trials": n_trials, "alpha": ALPHA, "miss_floor": MISS_FLOOR,
            "min_evidence": MIN_EVIDENCE,
            "spec": {k: str(v) for k, v in vars(spec).items()},
            "real_records": len(records) if records else 0,
        },
        "conditions": out,
        "degradation_curve": [
            {
                "condition": label,
                "residual_proxy": out[label]["residual_proxy_mean"],
                "content_aware": out[label]["summary"]["content-aware"]["infected_mean"],
                "open_world": out[label]["summary"]["open-world"]["infected_mean"],
                "greedy_blocking": out[label]["summary"]["greedy-blocking"]["infected_mean"],
                "alarm_rate": out[label]["alarm_rate"],
            }
            for label, _, _ in conditions
        ],
        "tests": tests,
    }
    os.makedirs("results", exist_ok=True)
    with open("results/open_world.json", "w") as f:
        json.dump(payload, f, indent=2)
    print("\nwrote results/open_world.json")


if __name__ == "__main__":
    main()
