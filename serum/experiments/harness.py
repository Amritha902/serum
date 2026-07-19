"""Reproducible comparison of containment policies across random outbreaks.

Every trial draws a fresh network, payload, and seed set from a single seeded
RNG stream, then replays the *identical* outbreak under each policy (same graph,
same payload, same seeds, same spread randomness) so differences are due to the
policy alone -- a paired design that slashes variance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import mean, pstdev
from typing import Callable

import numpy as np

from serum.agents.content_aware import (
    ContentAwareAgent,
    OracleAfterDelay,
    OracleContentAware,
)
from serum.baselines.heuristics import (
    AcquaintanceDefense,
    BetweennessDefense,
    DegreeDefense,
    EigenvectorDefense,
    GreedyBlockingDefense,
    NoDefense,
    RandomDefense,
)
from serum.sim.environment import ContainmentEnv
from serum.sim.network import generate_network
from serum.sim.payload import sample_payload


@dataclass
class TrialSpec:
    n: int = 500
    topology: str = "ba"
    m: int = 3
    n_cves: int = 12
    vuln_lambda: float = 6.0
    popularity_alpha: float = 0.8
    beta: float = 0.35
    payload_strategy: str = "band"
    prev_band: tuple = (0.20, 0.60)
    n_seeds: int = 3
    budget_per_step: int = 5
    horizon: int = 40
    n_products: int = 80          # real-data: software-universe size
    n_segments: int = 12          # real-data: network zones (subnets/VLANs)
    homophily: float = 0.5        # real-data: software monoculture within a zone


def build_episode(spec: TrialSpec, seed: int, records=None):
    """Construct one fully-specified outbreak (network + payload + seeds).

    If ``records`` (cleaned CVERecords) are supplied, the network is built from
    real NVD-derived vulnerability profiles and transmissibility is grounded in
    each CVE's CVSS; otherwise the synthetic Zipf model is used.

    Returns a factory that yields a *fresh* env with identical dynamics RNG for
    each policy, so every policy faces the same stochastic outbreak."""
    gen_rng = np.random.default_rng(seed)
    if records is not None:
        from serum.data.profiles import generate_real_network
        g = generate_real_network(
            records, n=spec.n, topology=spec.topology, m=spec.m,
            n_cves=spec.n_cves, n_products=spec.n_products,
            n_segments=spec.n_segments, homophily=spec.homophily, rng=gen_rng,
        )
    else:
        g = generate_network(
            n=spec.n,
            topology=spec.topology,
            m=spec.m,
            n_cves=spec.n_cves,
            vuln_lambda=spec.vuln_lambda,
            popularity_alpha=spec.popularity_alpha,
            rng=gen_rng,
        )
    payload = sample_payload(g, beta=spec.beta, strategy=spec.payload_strategy,
                             rng=gen_rng, band=spec.prev_band)
    # Seed the outbreak among hosts that actually carry the payload's CVE,
    # otherwise patient zero cannot spread at all.
    carriers = [v for v, d in g.nodes(data=True) if payload.cve in d["vuln"]]
    if len(carriers) < spec.n_seeds:
        carriers = list(g.nodes())
    seeds = list(gen_rng.choice(carriers, size=spec.n_seeds, replace=False))
    seeds = [int(s) for s in seeds]

    def factory():
        # A per-episode dynamics RNG, re-derived from the same seed so that
        # every policy sees the same infection coin-flips.
        dyn_rng = np.random.default_rng(seed + 10_000_019)
        return ContainmentEnv(
            g=g,
            payload=payload,
            seeds=seeds,
            budget_per_step=spec.budget_per_step,
            horizon=spec.horizon,
            rng=dyn_rng,
        )

    return factory, payload


def default_policies(g, rng):
    """The standard comparison lineup, freshly constructed per trial."""
    return [
        NoDefense(),
        RandomDefense(rng=rng),
        AcquaintanceDefense(rng=rng),
        DegreeDefense(),
        EigenvectorDefense(),
        BetweennessDefense(),
        GreedyBlockingDefense(),
        OracleAfterDelay(delay=5),            # realistic: threat intel arrives late
        ContentAwareAgent(g),                 # ours, partial observation
        OracleContentAware(patch=True),       # ours, full-observation upper bound
    ]


@dataclass
class PolicyStats:
    name: str
    infected_fraction: list = field(default_factory=list)
    availability: list = field(default_factory=list)
    steps_to_containment: list = field(default_factory=list)

    def summary(self):
        def ms(xs):
            return (round(mean(xs), 4), round(pstdev(xs), 4)) if xs else (float("nan"), 0.0)
        return {
            "name": self.name,
            "infected_fraction": ms(self.infected_fraction),
            "availability": ms(self.availability),
            "steps_to_containment": ms(self.steps_to_containment),
        }


def compare_policies(spec: TrialSpec, n_trials: int = 20, base_seed: int = 0,
                     verbose=True, records=None):
    """Run all policies over ``n_trials`` paired outbreaks; return per-policy stats.

    Pass ``records`` (cleaned CVERecords) to run on real NVD-derived networks."""
    stats: dict[str, PolicyStats] = {}
    curves: dict[str, list] = {}
    for t in range(n_trials):
        seed = base_seed + t
        factory, payload = build_episode(spec, seed, records=records)
        # policies constructed against this trial's graph
        probe_env = factory()
        pol_rng = np.random.default_rng(seed + 777)
        policies = default_policies(probe_env.g, pol_rng)
        for policy in policies:
            env = factory()
            res = env.run(policy)
            stats.setdefault(policy.name, PolicyStats(policy.name))
            s = stats[policy.name]
            s.infected_fraction.append(res.infected_fraction)
            s.availability.append(res.availability)
            s.steps_to_containment.append(res.steps_to_containment)
            curves.setdefault(policy.name, []).append(res.trace)
        if verbose:
            print(f"  trial {t + 1}/{n_trials} (cve={payload.cve}) done", flush=True)
    return stats, curves


STRUCT_NAMES = ("degree", "eigenvector", "betweenness", "greedy-blocking", "acquaintance")


def _paired_vs(ca, comp, n_boot, seed):
    from scipy import stats as ss
    diff = comp - ca                               # >0 == content-aware wins
    rng = np.random.default_rng(seed)
    idx = np.arange(len(diff))
    boots = np.array([diff[rng.choice(idx, size=len(idx), replace=True)].mean()
                      for _ in range(n_boot)])
    lo, hi = np.percentile(boots, [2.5, 97.5])
    try:
        _, p = ss.wilcoxon(ca, comp)
    except ValueError:
        p = float("nan")
    return {
        "mean_abs_reduction": float(diff.mean()),
        "mean_rel_reduction": float((diff / np.maximum(comp, 1e-9)).mean()),
        "ci95_abs": (float(lo), float(hi)),
        "p_value": float(p),
        "wins": int((diff > 0).sum()),
    }


def paired_report(stats, n_boot: int = 5000, seed: int = 0):
    """Paired comparison of the content-aware agent against structure-only
    defenders, on the two comparators a reviewer will ask for.

    - ``primary`` (the deployable claim): vs the single structural baseline with
      the best *mean* performance -- the one you'd actually choose in advance.
    - ``ensemble`` (a stress test): vs the per-trial *best* of all structural
      baselines -- an oracle that cherry-picks the winning heuristic on every
      outbreak. Beating a single baseline is the real claim; matching the
      ensemble oracle is a bonus.

    Each reports mean infection reduction, a bootstrap 95% CI, a paired Wilcoxon
    p-value, and win count."""
    if "content-aware" not in stats:
        return None
    struct = [n for n in STRUCT_NAMES if n in stats]
    if not struct:
        return None
    ca = np.array(stats["content-aware"].infected_fraction, dtype=float)
    means = {n: float(np.mean(stats[n].infected_fraction)) for n in struct}
    best_name = min(means, key=means.get)          # strongest on average
    best_fixed = np.array(stats[best_name].infected_fraction, dtype=float)
    mat = np.vstack([np.array(stats[n].infected_fraction, dtype=float) for n in struct])
    ensemble = mat.min(axis=0)

    return {
        "n_trials": int(len(ca)),
        "primary": {"vs": best_name, **_paired_vs(ca, best_fixed, n_boot, seed)},
        "ensemble": {"vs": "best-of-{" + ",".join(struct) + "}",
                     **_paired_vs(ca, ensemble, n_boot, seed)},
    }


def evaluate_policy(spec: TrialSpec, policy_factory: Callable, n_trials=20, base_seed=0):
    """Evaluate a single custom policy factory across trials."""
    out = PolicyStats(getattr(policy_factory, "name", "custom"))
    for t in range(n_trials):
        factory, _ = build_episode(spec, base_seed + t)
        env = factory()
        res = env.run(policy_factory(env.g))
        out.infected_fraction.append(res.infected_fraction)
        out.availability.append(res.availability)
        out.steps_to_containment.append(res.steps_to_containment)
    return out
