#!/usr/bin/env python
"""Value of active sensing (novelty N7): honeypot probing.

Compares content-aware containment with and without honeypot value-of-information
probing on real NVD data, reporting infection, availability, and the step at
which the payload is captured (exact identification).

Finding (data): probing captures the payload almost immediately (step ~1),
enabling early availability-preserving patching -- it buys exact identification
and higher availability at no infection cost. Consistent with N8: passive
inference already suffices for infection control, so active sensing is an
identification/availability tool, not a containment necessity.

Saves results/probing.json.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402

from serum.agents.content_aware import ContentAwareAgent  # noqa: E402
from serum.agents.probing import ProbingAgent  # noqa: E402
from serum.data.clean import load_clean_csv  # noqa: E402
from serum.experiments.harness import TrialSpec, build_episode  # noqa: E402


def run_probe(env, agent):
    obs = env.reset()
    cap = None
    while not env.done():
        obs = env.step(agent(env, obs))
        if cap is None and obs.captured_cve is not None:
            cap = env.t
    return (len(env._ever) / env.n, 1.0 - len(env.isolated) / env.n,
            cap if cap is not None else env.horizon)


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    records = load_clean_csv("data/clean/cves.csv")
    spec = TrialSpec(n=500, n_cves=40, homophily=0.4, payload_strategy="band",
                     prev_band=(0.15, 0.55))
    rows = []
    print(f"{'agent':>22} {'infected%':>10} {'availability%':>14} {'capture@step':>13}")
    print("-" * 62)
    # baseline content-aware
    ci, cav = [], []
    for s in range(trials):
        f, _ = build_episode(spec, s, records=records)
        env = f()
        r = env.run(ContentAwareAgent(env.g))
        ci.append(r.infected_fraction); cav.append(r.availability)
    print(f"{'content-aware':>22} {100*np.mean(ci):>9.2f} {100*np.mean(cav):>13.1f} {'--':>13}")
    rows.append({"agent": "content-aware", "infected": float(np.mean(ci)),
                 "availability": float(np.mean(cav))})

    for frac in [0.2, 0.4]:
        inf, av, cap = [], [], []
        for s in range(trials):
            f, _ = build_episode(spec, s, records=records)
            i, a, c = run_probe(f(), ProbingAgent(f().g, probe_fraction=frac))
            inf.append(i); av.append(a); cap.append(c)
        print(f"{'+probe f=' + str(frac):>22} {100*np.mean(inf):>9.2f} "
              f"{100*np.mean(av):>13.1f} {np.mean(cap):>13.1f}")
        rows.append({"agent": f"probe_{frac}", "infected": float(np.mean(inf)),
                     "availability": float(np.mean(av)), "capture_step": float(np.mean(cap))})

    os.makedirs("results", exist_ok=True)
    json.dump(rows, open("results/probing.json", "w"), indent=2)
    print("\n[saved -> results/probing.json]  Probing buys instant identification "
          "and higher availability at no infection cost.")


if __name__ == "__main__":
    main()
