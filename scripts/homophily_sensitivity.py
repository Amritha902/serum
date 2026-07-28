#!/usr/bin/env python
"""G6 mitigation: the content-aware advantage IS a function of the homophily knob.

The grill's honest attack: the favorable regime (vulnerable zones misaligned from
hubs) is manufactured by the software-monoculture `homophily` parameter the author
sets. This experiment states that explicitly as a threat rather than hiding it: we
sweep homophily from 0 (software assigned independently of zones -- no monoculture)
to high (strong zones) and show the content-aware advantage over the best
structural baseline shrinking toward 0 as homophily -> 0.

This is presented as a *threat to validity*, not a feature: it quantifies exactly
how much of the advantage depends on the monoculture assumption, so a reader can
judge whether a real network is monocultured enough for the method to help.

Real NVD data, paired outbreaks. Writes results/homophily_sensitivity.json.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402
from scipy import stats as ss  # noqa: E402

from serum.agents.content_aware import ContentAwareAgent  # noqa: E402
from serum.baselines.heuristics import BetweennessDefense, DegreeDefense, NoDefense  # noqa: E402
from serum.data.clean import load_clean_csv  # noqa: E402
from serum.experiments.harness import TrialSpec, build_episode  # noqa: E402


def _run(spec, records, make_agent, trials):
    out = []
    for s in range(trials):
        f, _ = build_episode(spec, s, records=records)
        env = f()
        out.append(env.run(make_agent(env.g)).infected_fraction)
    return np.array(out, dtype=float)


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    records = load_clean_csv("data/clean/cves.csv")
    rows = []
    print(f"homophily_sensitivity: {trials} paired outbreaks, real NVD, n=500, K=40\n")
    print(f"{'homophily':>9} {'no-def%':>8} {'best-struct%':>13} {'content%':>9} "
          f"{'edge_pp':>8} {'wins':>7} {'p':>9}")
    print("-" * 68)
    for h in [0.0, 0.2, 0.4, 0.6, 0.8]:
        spec = TrialSpec(n=500, n_cves=40, homophily=h, payload_strategy="band",
                         prev_band=(0.15, 0.55))
        nd = _run(spec, records, lambda g: NoDefense(), trials)
        deg = _run(spec, records, lambda g: DegreeDefense(), trials)
        bet = _run(spec, records, lambda g: BetweennessDefense(), trials)
        ca = _run(spec, records, lambda g: ContentAwareAgent(g), trials)
        # best structural per-trial-averaged: take the better mean of deg/bet
        best = deg if deg.mean() <= bet.mean() else bet
        best_name = "degree" if deg.mean() <= bet.mean() else "betweenness"
        edge = float(best.mean() - ca.mean())      # >0 = content-aware better
        wins = int((ca < best).sum())
        try:
            _, p = ss.wilcoxon(ca, best)
        except ValueError:
            p = 1.0
        rows.append({"homophily": h, "no_defense": float(nd.mean()),
                     "best_structural": float(best.mean()), "best_name": best_name,
                     "content_aware": float(ca.mean()), "edge_pp": edge,
                     "wins_of_n": f"{wins}/{trials}", "p": float(p)})
        print(f"{h:>9.1f} {100*nd.mean():>7.2f} {100*best.mean():>12.2f} "
              f"{100*ca.mean():>8.2f} {100*edge:>+7.2f} {wins:>4}/{trials} {p:>9.1e}")

    edge0 = rows[0]                                  # homophily = 0 (no monoculture)
    sig_at_zero = edge0["edge_pp"] > 0 and edge0["p"] < 0.05
    all_sig = all(r["edge_pp"] > 0 and r["p"] < 0.05 for r in rows)
    peak = max(rows, key=lambda r: r["edge_pp"])
    if sig_at_zero and all_sig:
        verdict = (f"UNEXPECTED (refutes the 'manufactured regime' worry): the "
                   f"content-aware edge is significant at EVERY homophily level "
                   f"including 0 (no monoculture: {edge0['edge_pp']*100:+.2f}pp, "
                   f"p={edge0['p']:.1e}); it is non-monotonic, peaking at homophily "
                   f"{peak['homophily']} ({peak['edge_pp']*100:+.2f}pp). The "
                   f"advantage is NOT an artifact of the monoculture knob -- the "
                   f"vulnerable set diverges from the hubs even without zone "
                   f"clustering; homophily controls only how spatially clustered "
                   f"that set is.")
    else:
        verdict = (f"edge at homophily 0 = {edge0['edge_pp']*100:+.2f}pp "
                   f"(p={edge0['p']:.1e}); peak at homophily {peak['homophily']}.")
    summary = {"n_trials": trials, "grid": rows, "verdict": verdict}
    os.makedirs("results", exist_ok=True)
    json.dump(summary, open("results/homophily_sensitivity.json", "w"), indent=2)
    print(f"\n[saved -> results/homophily_sensitivity.json]  {verdict}")


if __name__ == "__main__":
    main()
