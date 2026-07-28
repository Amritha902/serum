#!/usr/bin/env python
"""G1 mitigation: content-aware vs the two CLOSEST prior systems, head-to-head.

The grill's existential finding: CyGym (static exploit prior, no online update)
and DAVA (data-aware, exploit-blind) are named as the nearest systems but never
run. This puts both in the harness against the content-aware agent on identical
paired outbreaks over real NVD data, and reports the honest paired result.

Two comparisons carry the paper's novelty:
  * content-aware vs DAVA -- does reasoning about the *exploit* beat reasoning
    about the *observed infection*? (tests content-awareness itself)
  * content-aware vs CyGym-static -- does *online inference* beat a *static
    prior*? (tests the specific gap SERUM claims to fill; L2 predicts this gap
    is small, so we expect an honest, possibly-insignificant result here)

Writes results/closest_baselines.json.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402
from scipy import stats as ss  # noqa: E402

from serum.agents.content_aware import ContentAwareAgent, OracleContentAware  # noqa: E402
from serum.baselines.closest import DavaDefense, StaticPriorDefense  # noqa: E402
from serum.baselines.heuristics import DegreeDefense, NoDefense  # noqa: E402
from serum.data.clean import load_clean_csv  # noqa: E402
from serum.experiments.harness import TrialSpec, build_episode  # noqa: E402


def _run(spec, records, make_agent, trials):
    inf, avail = [], []
    for s in range(trials):
        f, _ = build_episode(spec, s, records=records)
        env = f()
        r = env.run(make_agent(env.g))
        inf.append(r.infected_fraction)
        avail.append(r.availability)
    return np.array(inf, dtype=float), np.array(avail, dtype=float)


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    records = load_clean_csv("data/clean/cves.csv")
    spec = TrialSpec(n=500, n_cves=40, homophily=0.4, payload_strategy="band",
                     prev_band=(0.15, 0.55))

    policies = {
        "no-defense": lambda g: NoDefense(),
        "degree": lambda g: DegreeDefense(),
        "dava": lambda g: DavaDefense(),
        "cygym-static": lambda g: StaticPriorDefense(g),
        "content-aware": lambda g: ContentAwareAgent(g),
        "content-aware-oracle": lambda g: OracleContentAware(),
    }

    inf, avail = {}, {}
    for name, mk in policies.items():
        inf[name], avail[name] = _run(spec, records, mk, trials)

    def paired(a, b):
        da, db = inf[a], inf[b]
        gap = float(db.mean() - da.mean())      # >0 means `a` (ours) is better
        wins = int((da < db).sum())
        try:
            _, p = ss.wilcoxon(da, db)
        except ValueError:
            p = 1.0
        return {"mean_ours": float(da.mean()), "mean_them": float(db.mean()),
                "abs_reduction": gap, "rel_reduction": gap / db.mean() if db.mean() else 0.0,
                "wins_of_n": f"{wins}/{trials}", "paired_wilcoxon_p": float(p)}

    vs_dava = paired("content-aware", "dava")
    vs_cygym = paired("content-aware", "cygym-static")

    print(f"closest_baselines: {trials} paired outbreaks, real NVD, n=500, K=40\n")
    print(f"{'policy':>22} {'infected%':>10} {'availability%':>14}")
    print("-" * 50)
    for name in policies:
        print(f"{name:>22} {100*inf[name].mean():>9.2f} {100*avail[name].mean():>13.2f}")
    print()
    print(f"content-aware vs DAVA (data-aware, exploit-blind):  "
          f"{100*vs_dava['abs_reduction']:+.2f}pp "
          f"({100*vs_dava['rel_reduction']:+.1f}%), wins {vs_dava['wins_of_n']}, "
          f"p={vs_dava['paired_wilcoxon_p']:.2e}")
    print(f"content-aware vs CyGym-static (static prior, no online update):  "
          f"{100*vs_cygym['abs_reduction']:+.2f}pp "
          f"({100*vs_cygym['rel_reduction']:+.1f}%), wins {vs_cygym['wins_of_n']}, "
          f"p={vs_cygym['paired_wilcoxon_p']:.2e}")

    summary = {
        "n_trials": trials, "n_hosts": 500, "K": 40,
        "means_infected": {k: float(v.mean()) for k, v in inf.items()},
        "means_availability": {k: float(v.mean()) for k, v in avail.items()},
        "content_aware_vs_dava": vs_dava,
        "content_aware_vs_cygym_static": vs_cygym,
    }
    os.makedirs("results", exist_ok=True)
    json.dump(summary, open("results/closest_baselines.json", "w"), indent=2)
    print("\n[saved -> results/closest_baselines.json]")


if __name__ == "__main__":
    main()
