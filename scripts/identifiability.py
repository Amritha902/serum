#!/usr/bin/env python
"""Empirically validate the identifiability theorem.

For each CVE the theorem predicts, from vulnerability profiles alone, whether a
saturating outbreak pins the posterior to the true CVE (identifiable) or leaves
residual confusers. We then *run* a full no-defense outbreak of each CVE, let the
hard-consistency belief converge, and check that:

    belief recovers the true CVE exactly  <=>  theorem says identifiable.

Agreement near 100% is the empirical proof that the combinatorial condition on
CVE profiles governs exploit-identifiability.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402

from serum.data.clean import load_clean_csv  # noqa: E402
from serum.data.profiles import generate_real_network  # noqa: E402
from serum.inference.belief import CVEBelief  # noqa: E402
from serum.inference.identifiability import (  # noqa: E402
    carriers, confusers, identifiability_report, is_identifiable,
    reachable_component,
)
from serum.sim.environment import ContainmentEnv  # noqa: E402
from serum.sim.network import generate_network  # noqa: E402
from serum.sim.payload import Payload  # noqa: E402
from serum.baselines.heuristics import NoDefense  # noqa: E402


def run_belief_to_convergence(g, cve, seeds, beta=1.0):
    """Run a *saturating* no-defense outbreak (deterministic beta=1 so the worm
    covers its whole reachable vulnerable component) and return the belief's MAP
    CVE and exact posterior support. known_seeds=False so all infected hosts --
    the whole component R -- inform the belief, matching the theorem's supp(R)."""
    payload = Payload(cve=cve, beta=beta)
    env = ContainmentEnv(g, payload, seeds, horizon=200, rng=np.random.default_rng(7))
    belief = CVEBelief(g, mode="hard", known_seeds=False)
    obs = env.reset()
    for _ in range(env.horizon):
        belief.update(obs.newly_infected, obs.seeds)
        if env.done():
            break
        obs = env.step([])
    return belief.map_cve(), belief.support_size(), len(env._ever)


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 6
    use_real = "--synth" not in sys.argv
    records = load_clean_csv("data/clean/cves.csv") if use_real and \
        os.path.exists("data/clean/cves.csv") else None

    agree = tot = 0
    id_frac = []
    for t in range(trials):
        rng = np.random.default_rng(t)
        if records is not None:
            g = generate_real_network(records, n=400, n_cves=30, n_products=70,
                                      homophily=0.4, rng=rng)
        else:
            g = generate_network(n=400, n_cves=16, vuln_lambda=5, popularity_alpha=0.7, rng=rng)
        rep = identifiability_report(g)
        id_frac.append(rep["identifiable_fraction"])

        for c in range(g.graph["n_cves"]):
            car = carriers(g, c)
            R = reachable_component(g, c)
            if len(R) < 5:            # need a non-trivial outbreak to observe
                continue
            seeds = [int(x) for x in
                     np.random.default_rng(1000 + c).choice(sorted(R),
                     size=min(3, len(R)), replace=False)]
            theory = is_identifiable(g, c)
            map_cve, supp, ninf = run_belief_to_convergence(g, c, seeds)
            # belief "recovered" the truth iff it converged to a singleton == c
            recovered = (map_cve == c and supp == 1)
            # a fair comparison also accepts: theory-confusers explain a non-singleton
            empirical_identifiable = recovered
            if empirical_identifiable == theory:
                agree += 1
            tot += 1

    print(f"identifiable fraction (theory, mean over networks): {np.mean(id_frac):.2f}")
    print(f"theorem <-> belief agreement: {agree}/{tot} = {100*agree/max(1,tot):.1f}%")
    print("(agreement ~100% == the combinatorial CVE-profile condition governs "
          "exploit-identifiability)")


if __name__ == "__main__":
    main()
