#!/usr/bin/env python
"""The inventory-allocation game: which asset coverage gaps can you afford?

Setup. ``scripts/open_world.py`` established that the content-aware advantage is
governed by carrier-set **proxy coverage**: an exploit the defender has never
catalogued is still contained if some catalogued vulnerability lives on the same
machines, and the advantage decays to exactly zero as that proxy disappears.

That result has a consequence the previous experiments could not see, because
they all held the catalog fixed and asked which *policy* wins. Once proxy
coverage is what matters, the defender's real decision is **which products to
inventory** -- asset coverage is a budget, no CMDB is complete -- and the
attacker gets a corresponding move: pick the exploit sitting in whatever blind
spot that budget leaves.

This script plays that game.

Defender's move (allocate ``m`` of ``K`` CVEs to the catalog):
  * ``full``        -- no gaps (m = K). The assumption every earlier result made.
  * ``prevalence``  -- inventory the most widespread software. This is what
                       "improve our asset coverage" means in practice.
  * ``random``      -- coverage with no strategy behind it.
  * ``maximin``     -- greedily maximise the *worst* proxy coverage left
                       uncovered (``allocate_maximin_proxy``).

Attacker's move:
  * ``band``      -- the naive attacker used by every previous experiment:
                     sample a mid-prevalence CVE, ignoring the catalog.
  * ``blindspot`` -- best-respond to the allocation: among CVEs that can still
                     sustain an outbreak, take the one with the least proxy
                     coverage. This is a genuine tradeoff for the attacker, not a
                     free win -- idiosyncratic software sits on fewer hosts, so
                     the best evasion is often a worse spreader.

Predictions:
  P1. Under the naive attacker the allocation strategy barely matters -- which is
      why holding the catalog fixed made this whole dimension invisible.
  P2. Under the blind-spot attacker, prevalence allocation loses most of the
      content-aware advantage: covering the most common software is the wrong
      objective when the attacker picks what you cannot see.
  P3. At *equal inventory budget*, maximin allocation retains more advantage than
      prevalence. If it does not, the actionable claim dies and we say so.

Writes ``results/catalog_game.json``.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402
from scipy import stats as ss  # noqa: E402

from serum.agents.content_aware import ContentAwareAgent  # noqa: E402
from serum.agents.openworld import OpenWorldAgent  # noqa: E402
from serum.attack.catalog_attack import (  # noqa: E402
    allocate_maximin_proxy,
    allocate_prevalence,
    allocate_random,
    select_blindspot_payload,
    worst_case_proxy,
)
from serum.baselines.heuristics import GreedyBlockingDefense, NoDefense  # noqa: E402
from serum.data.clean import load_clean_csv  # noqa: E402
from serum.experiments.harness import TrialSpec, build_episode  # noqa: E402
from serum.sim.catalog import restrict_catalog, true_carriers  # noqa: E402
from serum.sim.environment import ContainmentEnv  # noqa: E402
from serum.sim.payload import sample_payload  # noqa: E402

COVERAGE_FRACTION = 0.4    # the defender inventories 40% of the CVE universe
MIN_COMPONENT = 20         # a CVE must be able to reach this many hosts to be a threat
SPREAD_FLOOR = 0.5         # ...and at least half the reach of the best exploit available

# Different allocations provoke different attacker choices, and those exploits
# differ in raw severity -- so raw infected fractions are not comparable across
# cells. Every headline number below is therefore *containment efficacy*,
# (no-defense - policy) / no-defense: the share of the outbreak the defender
# actually prevented, which is comparable across outbreaks of different size.


def _paired_p(a, b):
    a, b = np.asarray(a, float), np.asarray(b, float)
    if len(a) == 0 or np.allclose(a, b):
        return float("nan")
    try:
        return float(ss.wilcoxon(a, b).pvalue)
    except ValueError:
        return float("nan")


def _allocate(g, strategy, m, rng):  # noqa: D401
    if strategy == "full":
        return frozenset(range(int(g.graph["n_cves"])))
    if strategy == "prevalence":
        return allocate_prevalence(g, m, min_component=MIN_COMPONENT)
    if strategy == "random":
        return allocate_random(g, m, rng=rng)
    if strategy == "maximin":
        return allocate_maximin_proxy(g, m, min_component=MIN_COMPONENT)
    raise ValueError(strategy)


def _episode(g, payload, spec, seed):
    """A fresh env on this graph with a chosen payload, seeded among its carriers."""
    rng = np.random.default_rng(seed + 4242)
    carriers = sorted(true_carriers(g, payload.cve)) or sorted(g.nodes())
    k = min(spec.n_seeds, len(carriers))
    seeds = [int(v) for v in rng.choice(carriers, size=k, replace=False)]

    def factory():
        return ContainmentEnv(
            g=g, payload=payload, seeds=seeds,
            budget_per_step=spec.budget_per_step, horizon=spec.horizon,
            rng=np.random.default_rng(seed + 10_000_019),
        )
    return factory


def run_cell(spec, n_trials, records, allocation: str, attacker: str,
             coverage: float = COVERAGE_FRACTION):
    """One (allocation, attacker) cell of the game matrix."""
    infected = {"content-aware": [], "greedy-blocking": [],
                "open-world": [], "no-defense": []}
    exposures, chosen = [], []

    for t in range(n_trials):
        seed = t
        factory0, _ = build_episode(spec, seed, records=records)
        g = factory0().g0
        rng = np.random.default_rng(seed + 99)

        m = max(1, int(round(coverage * int(g.graph["n_cves"]))))
        covered = _allocate(g, allocation, m, rng)
        restrict_catalog(g, covered)
        exposures.append(worst_case_proxy(g, covered, min_component=MIN_COMPONENT,
                                          spread_floor_frac=SPREAD_FLOOR))

        if attacker == "blindspot":
            payload = select_blindspot_payload(
                g, beta=spec.beta, covered=covered, min_component=MIN_COMPONENT,
                spread_floor_frac=SPREAD_FLOOR,
            )
        else:
            payload = sample_payload(g, beta=spec.beta, strategy="band",
                                     rng=rng, band=spec.prev_band)
        chosen.append(int(payload.cve) in set(covered))

        factory = _episode(g, payload, spec, seed)
        for name, pol in (
            ("no-defense", NoDefense()),
            ("greedy-blocking", GreedyBlockingDefense()),
            ("content-aware", ContentAwareAgent(g)),
            ("open-world", OpenWorldAgent(g)),
        ):
            infected[name].append(factory().run(pol).infected_fraction)

    ca = np.array(infected["content-aware"], float)
    gb = np.array(infected["greedy-blocking"], float)
    nd = np.array(infected["no-defense"], float)

    # Containment efficacy, per trial, so cells with different outbreak severity
    # remain comparable. Guarded against trials where nothing spread at all.
    ok = nd > 0
    eff_ca = np.where(ok, (nd - ca) / np.where(ok, nd, 1.0), 0.0)
    eff_gb = np.where(ok, (nd - gb) / np.where(ok, nd, 1.0), 0.0)

    adv = float((gb.mean() - ca.mean()) / gb.mean()) if gb.mean() > 0 else 0.0
    return {
        "means": {k: round(float(np.mean(v)), 5) for k, v in infected.items()},
        "efficacy_content": round(float(eff_ca.mean()), 4),
        "efficacy_structural": round(float(eff_gb.mean()), 4),
        "efficacy_gap": round(float((eff_ca - eff_gb).mean()), 4),
        "p_efficacy_gap": _paired_p(eff_ca, eff_gb),
        "advantage_over_structural": round(adv, 4),
        "worst_case_proxy": round(float(np.mean(exposures)), 4),
        "attacker_picked_covered_cve": round(float(np.mean(chosen)), 3),
        "raw": {k: [round(x, 5) for x in v] for k, v in infected.items()},
        "raw_efficacy": {"content": [round(x, 5) for x in eff_ca],
                         "structural": [round(x, 5) for x in eff_gb]},
    }


def main():
    n_trials = int(os.environ.get("SERUM_TRIALS", 30))
    records = (load_clean_csv("data/clean/cves.csv")
               if os.path.exists("data/clean/cves.csv") else None)
    spec = TrialSpec(n=500, topology="email", n_cves=30, n_products=80,
                     n_segments=12, homophily=0.6, budget_per_step=5,
                     horizon=40, payload_strategy="band")

    print(f"[catalog-game] real NVD records: {len(records) if records else 0}; "
          f"trials={n_trials}; coverage={COVERAGE_FRACTION:.0%} of the CVE universe")

    grid = {}
    # Sweep the asset-coverage budget. The question is not "does content-awareness
    # win" but "how much of my software estate do I have to inventory before a
    # blind-spot attacker stops having a damaging exploit to reach for".
    for coverage in (0.1, 0.2, 0.3, 0.4, 0.6):
        print(f"\n  --- coverage = {coverage:.0%} of the CVE universe ---")
        for allocation in ("prevalence", "maximin"):
            for attacker in ("band", "blindspot"):
                key = f"cov{coverage:.1f}/{allocation}/{attacker}"
                cell = run_cell(spec, n_trials, records, allocation, attacker,
                                coverage=coverage)
                grid[key] = cell
                print(f"  {key:>34}  gap={cell['efficacy_gap']:+.3f}"
                      f" (p={cell['p_efficacy_gap']:.3g})"
                      f"  worst-proxy={cell['worst_case_proxy']:.3f}"
                      f"  attacker-had-to-use-covered-cve="
                      f"{cell['attacker_picked_covered_cve']:.2f}")

    # Full coverage, as the reference point every earlier experiment assumed.
    for attacker in ("band", "blindspot"):
        key = f"full/{attacker}"
        grid[key] = run_cell(spec, n_trials, records, "full", attacker, coverage=1.0)
        print(f"  {key:>34}  gap={grid[key]['efficacy_gap']:+.3f}"
              f" (p={grid[key]['p_efficacy_gap']:.3g})")

    def gap(k):
        return grid[k]["efficacy_gap"]

    tests = {
        # Where does popularity-driven coverage stop protecting you?
        "coverage_curve_prevalence_vs_blindspot": [
            {"coverage": c,
             "worst_proxy": grid[f"cov{c:.1f}/prevalence/blindspot"]["worst_case_proxy"],
             "gap_band": gap(f"cov{c:.1f}/prevalence/band"),
             "gap_blindspot": gap(f"cov{c:.1f}/prevalence/blindspot"),
             "forced_onto_covered_cve":
                 grid[f"cov{c:.1f}/prevalence/blindspot"]["attacker_picked_covered_cve"]}
            for c in (0.1, 0.2, 0.3, 0.4, 0.6)
        ],
        # Does allocating for proxy coverage beat allocating for popularity, at
        # equal budget, against the strategic attacker?
        "maximin_vs_prevalence_under_blindspot": [
            {"coverage": c,
             "maximin_gap": gap(f"cov{c:.1f}/maximin/blindspot"),
             "prevalence_gap": gap(f"cov{c:.1f}/prevalence/blindspot"),
             "maximin_worst_proxy":
                 grid[f"cov{c:.1f}/maximin/blindspot"]["worst_case_proxy"],
             "prevalence_worst_proxy":
                 grid[f"cov{c:.1f}/prevalence/blindspot"]["worst_case_proxy"],
             "p": _paired_p(
                 grid[f"cov{c:.1f}/maximin/blindspot"]["raw_efficacy"]["content"],
                 grid[f"cov{c:.1f}/prevalence/blindspot"]["raw_efficacy"]["content"])}
            for c in (0.1, 0.2, 0.3, 0.4, 0.6)
        ],
        "full_coverage_reference": {
            "gap_band": gap("full/band"), "gap_blindspot": gap("full/blindspot"),
        },
    }
    print("\n" + json.dumps(tests, indent=2))

    os.makedirs("results", exist_ok=True)
    with open("results/catalog_game.json", "w") as f:
        json.dump({
            "config": {"n_trials": n_trials,
                       "coverage_sweep": [0.1, 0.2, 0.3, 0.4, 0.6],
                       "min_component": MIN_COMPONENT,
                       "real_records": len(records) if records else 0},
            "grid": grid, "tests": tests,
        }, f, indent=2)
    print("\nwrote results/catalog_game.json")


if __name__ == "__main__":
    main()
