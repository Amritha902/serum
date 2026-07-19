#!/usr/bin/env python
"""Train the learned containment policy (N9) by the cross-entropy method.

Gradient-free, pure-numpy: sample weight vectors from a Gaussian, evaluate each
by mean infection over training outbreaks, keep the elite, refit, iterate. Trains
on real NVD data, then evaluates the learned policy against the hand-designed
content-aware agent and the best structural baseline on held-out seeds.

Saves results/policy.json (learned weights + eval).
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402

from serum.agents.content_aware import ContentAwareAgent  # noqa: E402
from serum.agents.learned import FEATURE_NAMES, N_FEATURES, LearnedPolicy  # noqa: E402
from serum.baselines.heuristics import BetweennessDefense, DegreeDefense  # noqa: E402
from serum.data.clean import load_clean_csv  # noqa: E402
from serum.experiments.harness import TrialSpec, build_episode  # noqa: E402


def mean_infection(spec, records, weights, seeds):
    vals = []
    for s in seeds:
        f, _ = build_episode(spec, s, records=records)
        env = f()
        vals.append(env.run(LearnedPolicy(env.g, weights=weights)).infected_fraction)
    return float(np.mean(vals))


def evaluate(spec, records, agent_factory, seeds):
    vals = []
    for s in seeds:
        f, _ = build_episode(spec, s, records=records)
        env = f()
        vals.append(env.run(agent_factory(env.g)).infected_fraction)
    return float(np.mean(vals))


def main():
    iters = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    pop, elite = 16, 4
    records = load_clean_csv("data/clean/cves.csv")
    spec = TrialSpec(n=400, n_cves=40, homophily=0.4, payload_strategy="band",
                     prev_band=(0.15, 0.55))
    train_seeds = list(range(12))
    test_seeds = list(range(500, 524))
    rng = np.random.default_rng(0)

    mu = np.array([1.0, 0.0, 0.0, 0.0, 0.0, 0.0])   # warm-start at the CA signal
    sigma = np.ones(N_FEATURES)
    best_w, best_score = mu.copy(), mean_infection(spec, records, mu, train_seeds)
    print(f"init (content-aware-like) train infection: {100*best_score:.2f}%")
    for it in range(iters):
        cands = rng.normal(mu, sigma, size=(pop, N_FEATURES))
        scores = np.array([mean_infection(spec, records, w, train_seeds) for w in cands])
        order = np.argsort(scores)          # lower infection = better
        elites = cands[order[:elite]]
        mu, sigma = elites.mean(0), elites.std(0) + 1e-2
        if scores[order[0]] < best_score:
            best_score, best_w = scores[order[0]], cands[order[0]].copy()
        print(f"iter {it+1}/{iters}: best train infection {100*best_score:.2f}%")

    # held-out evaluation
    learned = evaluate(spec, records, lambda g: LearnedPolicy(g, weights=best_w), test_seeds)
    ca = evaluate(spec, records, ContentAwareAgent, test_seeds)
    deg = evaluate(spec, records, lambda g: DegreeDefense(), test_seeds)
    bet = evaluate(spec, records, lambda g: BetweennessDefense(), test_seeds)
    out = {"weights": dict(zip(FEATURE_NAMES, best_w.tolist())),
           "held_out_infection": {"learned": learned, "content_aware": ca,
                                  "degree": deg, "betweenness": bet}}
    os.makedirs("results", exist_ok=True)
    json.dump(out, open("results/policy.json", "w"), indent=2)
    print("\n=== held-out infection (lower is better) ===")
    print(f"  learned       {100*learned:.2f}%")
    print(f"  content-aware {100*ca:.2f}%")
    print(f"  degree        {100*deg:.2f}%   betweenness {100*bet:.2f}%")
    print("learned weights:", {k: round(v, 2) for k, v in out["weights"].items()})
    print("[saved -> results/policy.json]")


if __name__ == "__main__":
    main()
