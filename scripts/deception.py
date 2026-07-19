#!/usr/bin/env python
"""Belief-poisoning deception attack (adversarial group testing).

The attacker plants decoy infections (hosts faked as infected via a side channel)
that do not carry the true CVE, to mislead the exploit inference. We compare the
content-aware agent under a soft vs hard belief as the number of decoys grows.

Honest finding: the soft belief resists LIGHT poisoning (a few decoys down-weight
rather than exclude the truth), but HEAVY poisoning overwhelms it (a soft
estimator eventually follows the weight of evidence); the hard belief's damage
SATURATES (one decoy excludes the truth; more do not worsen it, and the
confuser-shares-victims structure keeps its fallback sane). Neither fully solves
adversarial poisoning -- motivating a poisoning-robust (bounded-influence) belief.

Saves results/deception.json.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402

from serum.agents.content_aware import ContentAwareAgent  # noqa: E402
from serum.data.clean import load_clean_csv  # noqa: E402
from serum.experiments.harness import TrialSpec, build_episode  # noqa: E402


def run(spec, records, mode, trials):
    out = []
    for s in range(trials):
        f, _ = build_episode(spec, s, records=records)
        env = f()
        out.append(env.run(ContentAwareAgent(env.g, belief_mode=mode)).infected_fraction)
    return float(np.mean(out))


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    records = load_clean_csv("data/clean/cves.csv")
    rows = []
    print(f"{'decoys':>7} {'soft%':>8} {'hard%':>8}")
    print("-" * 26)
    for nd in [0, 5, 10, 15, 20, 30]:
        spec = TrialSpec(n=500, n_cves=40, homophily=0.4, payload_strategy="band",
                         prev_band=(0.15, 0.55), n_decoys=nd)
        soft = run(spec, records, "soft", trials)
        hard = run(spec, records, "hard", trials)
        rows.append({"decoys": nd, "soft": soft, "hard": hard})
        print(f"{nd:>7} {100*soft:>7.2f} {100*hard:>7.2f}")

    os.makedirs("results", exist_ok=True)
    json.dump(rows, open("results/deception.json", "w"), indent=2)
    print("\n[saved -> results/deception.json]  Soft belief resists light "
          "poisoning; heavy poisoning overwhelms it; hard-belief damage saturates.")


if __name__ == "__main__":
    main()
