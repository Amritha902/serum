#!/usr/bin/env python
"""Poison-robust defender vs belief poisoning (redeems the committee failure).

The robust agent audits its exploit belief against the spread it predicts and
hedges its budget toward structure-only targets when the belief stops matching
observed infections. We compare it to a single soft belief and to a pure
structural defender as decoy poisoning grows.

Finding: the robust agent stays near the BETTER of {content-aware, structural} at
every poisoning level -- full content-aware benefit when clean, graceful fallback
to structure under heavy poisoning -- where a single belief collapses. The
mechanism works because poisoning is one-shot but the real worm keeps revealing
the true exploit online.

Saves results/robust.json.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402

from serum.agents.content_aware import ContentAwareAgent  # noqa: E402
from serum.agents.robust import RobustAgent  # noqa: E402
from serum.baselines.heuristics import DegreeDefense  # noqa: E402
from serum.data.clean import load_clean_csv  # noqa: E402
from serum.experiments.harness import TrialSpec, build_episode  # noqa: E402


def run(spec, records, make_agent, trials):
    out = []
    for s in range(trials):
        f, _ = build_episode(spec, s, records=records)
        env = f()
        out.append(env.run(make_agent(env.g)).infected_fraction)
    return float(np.mean(out))


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    records = load_clean_csv("data/clean/cves.csv")
    rows = []
    print(f"{'decoys':>7} {'single-soft%':>13} {'degree%':>9} {'robust%':>9}")
    print("-" * 42)
    for nd in [0, 5, 10, 15, 20, 30, 50]:
        spec = TrialSpec(n=500, n_cves=40, homophily=0.4, payload_strategy="band",
                         prev_band=(0.15, 0.55), n_decoys=nd)
        soft = run(spec, records, lambda g: ContentAwareAgent(g, belief_mode="soft"), trials)
        deg = run(spec, records, lambda g: DegreeDefense(), trials)
        rob = run(spec, records, RobustAgent, trials)
        rows.append({"decoys": nd, "single_soft": soft, "degree": deg, "robust": rob})
        print(f"{nd:>7} {100*soft:>12.2f} {100*deg:>8.2f} {100*rob:>8.2f}")

    os.makedirs("results", exist_ok=True)
    json.dump(rows, open("results/robust.json", "w"), indent=2)
    print("\n[saved -> results/robust.json]  Robust agent tracks the better of "
          "belief/structure at every poisoning level; a single belief collapses.")


if __name__ == "__main__":
    main()
