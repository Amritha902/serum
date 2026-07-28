#!/usr/bin/env python
"""G2 mitigation: WHEN is online inference load-bearing (vs a static prior)?

The grill (G2) and the closest-baselines result (results/closest_baselines.json)
both show that under a GOOD (prevalence) prior, online belief update buys almost
nothing over CyGym's static prior (+0.19pp) -- consistent with the L2 ablation.
The honest question is not "does inference always help" (it doesn't) but "WHEN
does it help." This experiment answers it: online inference is load-bearing
exactly when the prior is *misleading*.

Setup. A realistic failure mode: the defender's prior points at the WRONG
exploit (bad threat intel, or a prior peaked on the loudest/most-prevalent CVE
that is not the one actually loose). We give BOTH defenders the same misleading
prior -- mass `concentration` on the single most-prevalent CVE -- and compare:
  * content-aware (online update): corrects the prior as the outbreak reveals the
    true target.
  * CyGym-static (no update): stuck defending the wrong subgraph forever.

We report the gap under the misleading prior next to the gap under the good
(prevalence) prior, so the contrast is explicit. Real NVD, paired.

Writes results/inference_value.json.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402
from scipy import stats as ss  # noqa: E402

from serum.agents.content_aware import ContentAwareAgent  # noqa: E402
from serum.baselines.closest import StaticPriorDefense  # noqa: E402
from serum.data.clean import load_clean_csv  # noqa: E402
from serum.experiments.harness import TrialSpec, build_episode  # noqa: E402
from serum.sim.network import cve_prevalence  # noqa: E402


def misleading_prior(g, concentration: float = 0.7):
    """A prior peaked on the single most-prevalent CVE -- the 'loud' exploit,
    which under band-sampled payloads is usually NOT the one actually loose."""
    prev = cve_prevalence(g)
    K = len(prev)
    p = np.full(K, (1.0 - concentration) / (K - 1))
    p[int(prev.argmax())] = concentration
    return p


def _paired(spec, records, make_a, make_b, trials):
    a, b = [], []
    for s in range(trials):
        fa, _ = build_episode(spec, s, records=records)
        ea = fa(); a.append(ea.run(make_a(ea.g)).infected_fraction)
        fb, _ = build_episode(spec, s, records=records)
        eb = fb(); b.append(eb.run(make_b(eb.g)).infected_fraction)
    a, b = np.array(a), np.array(b)
    gap = float(b.mean() - a.mean())
    wins = int((a < b).sum())
    try:
        _, p = ss.wilcoxon(a, b)
    except ValueError:
        p = 1.0
    return {"online_mean": float(a.mean()), "static_mean": float(b.mean()),
            "abs_reduction": gap, "rel_reduction": gap / b.mean() if b.mean() else 0.0,
            "wins_of_n": f"{wins}/{trials}", "p": float(p)}


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    records = load_clean_csv("data/clean/cves.csv")
    spec = TrialSpec(n=500, n_cves=40, homophily=0.4, payload_strategy="band",
                     prev_band=(0.15, 0.55))

    # good prior: both use the default prevalence prior
    good = _paired(spec, records,
                   lambda g: ContentAwareAgent(g),
                   lambda g: StaticPriorDefense(g),
                   trials)
    # misleading prior: both start peaked on the wrong (most-prevalent) CVE
    mis = _paired(spec, records,
                  lambda g: ContentAwareAgent(g, prior=misleading_prior(g)),
                  lambda g: StaticPriorDefense(g, prior=misleading_prior(g)),
                  trials)

    print(f"inference_value: {trials} paired outbreaks, real NVD, n=500, K=40\n")
    print(f"{'prior':>16} {'online%':>8} {'static%':>8} {'gap':>8} {'wins':>7} {'p':>9}")
    print("-" * 60)
    for label, r in [("good (prevalence)", good), ("misleading", mis)]:
        print(f"{label:>16} {100*r['online_mean']:>7.2f} {100*r['static_mean']:>7.2f} "
              f"{100*r['abs_reduction']:>+7.2f} {r['wins_of_n']:>7} {r['p']:>9.1e}")

    ratio = mis["abs_reduction"] / good["abs_reduction"] if good["abs_reduction"] else float("inf")
    verdict = (f"online inference is load-bearing under a misleading prior: "
               f"gap {mis['abs_reduction']*100:+.2f}pp (p={mis['p']:.1e}) vs only "
               f"{good['abs_reduction']*100:+.2f}pp under a good prior "
               f"(~{ratio:.0f}x larger)")
    summary = {"n_trials": trials, "good_prior": good, "misleading_prior": mis,
               "verdict": verdict}
    os.makedirs("results", exist_ok=True)
    json.dump(summary, open("results/inference_value.json", "w"), indent=2)
    print(f"\n[saved -> results/inference_value.json]  {verdict}")


if __name__ == "__main__":
    main()
