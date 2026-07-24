#!/usr/bin/env python
"""SR5 -- does the poison-robust defender survive an ADAPTIVE, audit-aware attacker?

`scripts/robust.py` showed RobustAgent beats belief poisoning, but only against a
*naive* poisoner that ignores the defender's trust audit. The fair objection: a
strawman built to lose. This experiment pits RobustAgent against the
**best-response** attacker (`attack/adaptive.py`) that knows the audit rule and
places decoys to keep the trust weight alpha high while still misdirecting.

Design (real NVD data, paired). For each decoy budget we run every policy through
the identical outbreak on the identical network:

  * ``DegreeDefense``     -- structure-only floor. A belief-free heuristic; NO
    poisoning can touch it, so it is the bar the robust agent must stay at or
    below. "Robust holds" == robust infection <= degree infection.
  * ``ContentAware(soft)`` vs the ADAPTIVE attacker -- a single belief with no
    audit; expected to be hurt most (shows the attack has teeth).
  * ``RobustAgent`` vs the NAIVE attacker   -- reproduces the prior win.
  * ``RobustAgent`` vs the ADAPTIVE attacker -- the actual SR5 test.

Report. Per budget: mean infection for each arm, and the *paired* gap
(robust-adaptive minus degree). Positive-and-significant means the adaptive
attacker beat the robust agent (an honest negative that bounds the claim);
<= 0 means the audit survives its own best response. We report whichever holds,
truthfully. Writes results/adaptive_attack.json.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402
from scipy import stats as ss  # noqa: E402

from serum.agents.content_aware import ContentAwareAgent  # noqa: E402
from serum.agents.robust import RobustAgent  # noqa: E402
from serum.baselines.heuristics import DegreeDefense  # noqa: E402
from serum.data.clean import load_clean_csv  # noqa: E402
from serum.experiments.harness import TrialSpec, build_episode  # noqa: E402


def run_paired(spec, records, make_agent, trials):
    """Per-trial infected fractions (paired: trial s uses the same seed s)."""
    out = []
    for s in range(trials):
        f, _ = build_episode(spec, s, records=records)
        env = f()
        out.append(env.run(make_agent(env.g)).infected_fraction)
    return np.array(out, dtype=float)


def _spec(nd, strategy):
    return TrialSpec(n=500, n_cves=40, homophily=0.4, payload_strategy="band",
                     prev_band=(0.15, 0.55), n_decoys=nd, decoy_strategy=strategy)


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    records = load_clean_csv("data/clean/cves.csv")
    rows = []
    print(f"adaptive_attack: {trials} paired trials/point, real NVD, n=500, K=40\n")
    print(f"{'decoys':>6} {'degree':>7} {'soft/adap':>10} {'rob/naive':>10} "
          f"{'rob/adap':>9} {'robAdap-deg':>12} {'p':>9} {'holds':>6}")
    print("-" * 78)
    for nd in [0, 5, 10, 15, 20, 30, 50]:
        deg = run_paired(_spec(nd, "adaptive"), records, lambda g: DegreeDefense(), trials)
        soft_ad = run_paired(_spec(nd, "adaptive"), records,
                             lambda g: ContentAwareAgent(g, belief_mode="soft"), trials)
        rob_na = run_paired(_spec(nd, "naive"), records, RobustAgent, trials)
        rob_ad = run_paired(_spec(nd, "adaptive"), records, RobustAgent, trials)

        gap = rob_ad - deg                       # >0 means poisoning beat the robust agent
        mean_gap = float(gap.mean())
        if nd == 0 or np.allclose(gap, 0.0):
            p = 1.0
        else:
            try:
                _, p = ss.wilcoxon(rob_ad, deg)
            except ValueError:
                p = 1.0
        holds = "yes" if not (mean_gap > 0 and p < 0.05) else "NO"
        rows.append({
            "decoys": nd,
            "degree": float(deg.mean()),
            "soft_adaptive": float(soft_ad.mean()),
            "robust_naive": float(rob_na.mean()),
            "robust_adaptive": float(rob_ad.mean()),
            "gap_robAdaptive_minus_degree": mean_gap,
            "paired_wilcoxon_p": float(p),
            "robust_holds": holds == "yes",
        })
        print(f"{nd:>6} {100*deg.mean():>6.2f} {100*soft_ad.mean():>9.2f} "
              f"{100*rob_na.mean():>9.2f} {100*rob_ad.mean():>8.2f} "
              f"{100*mean_gap:>+11.2f} {p:>9.1e} {holds:>6}")

    breached = [r for r in rows if not r["robust_holds"]]
    if breached:
        first = min(breached, key=lambda r: r["decoys"])
        verdict = (f"ADAPTIVE ATTACK BREACHES the robust agent at "
                   f"{first['decoys']} decoys (gap "
                   f"{first['gap_robAdaptive_minus_degree']*100:+.2f}pp, "
                   f"p={first['paired_wilcoxon_p']:.1e})")
    else:
        worst = max(rows, key=lambda r: r["gap_robAdaptive_minus_degree"])
        verdict = (f"robust agent HOLDS at every decoy level even under the "
                   f"audit-aware best response; worst paired gap vs structure "
                   f"floor {worst['gap_robAdaptive_minus_degree']*100:+.2f}pp "
                   f"(decoys={worst['decoys']}, p={worst['paired_wilcoxon_p']:.1e})")

    summary = {"n_trials": trials, "n_hosts": 500, "K": 40, "grid": rows,
               "verdict": verdict}
    os.makedirs("results", exist_ok=True)
    json.dump(summary, open("results/adaptive_attack.json", "w"), indent=2)
    print(f"\n[saved -> results/adaptive_attack.json]  {verdict}")


if __name__ == "__main__":
    main()
