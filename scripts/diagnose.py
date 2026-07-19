#!/usr/bin/env python
"""Diagnose the epidemic regime: prevalence, subgraph connectivity, take-off."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np, networkx as nx
from serum.sim.network import generate_network, cve_prevalence, vulnerable_subgraph
from serum.sim.payload import sample_payload
from serum.sim.environment import ContainmentEnv
from serum.baselines.heuristics import NoDefense

for lam, alpha, ncve, beta, strat in [
    (3.0, 1.3, 24, 0.35, "stealth"),
    (6.0, 0.8, 12, 0.15, "stealth"),
    (8.0, 0.6, 12, 0.12, "popular"),
    (10.0, 0.5, 10, 0.10, "stealth"),
]:
    rng = np.random.default_rng(0)
    g = generate_network(n=500, topology="ba", m=3, n_cves=ncve,
                         vuln_lambda=lam, popularity_alpha=alpha, rng=rng)
    prev = cve_prevalence(g)
    pl = sample_payload(g, beta=beta, strategy=strat, rng=rng)
    sub = vulnerable_subgraph(g, pl.cve)
    ncomp = nx.number_connected_components(sub) if sub.number_of_nodes() else 0
    giant = max((len(c) for c in nx.connected_components(sub)), default=0)
    carriers = [v for v,d in g.nodes(data=True) if pl.cve in d["vuln"]]
    seeds = [int(s) for s in rng.choice(carriers, size=min(3,len(carriers)), replace=False)]
    env = ContainmentEnv(g, pl, seeds, budget_per_step=5, horizon=40,
                         rng=np.random.default_rng(1))
    res = env.run(NoDefense())
    print(f"lam={lam} alpha={alpha} ncve={ncve} beta={beta} {strat}: "
          f"target-prev={prev[pl.cve]:.2f} carriers={len(carriers)} "
          f"giant-vuln-comp={giant} | NO-DEF infected={res.infected_fraction:.2%} "
          f"peak_step={res.steps_to_containment}")
