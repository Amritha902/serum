#!/usr/bin/env python
"""IoT-botnet (Mirai-style) headline experiment for SERUM.

Setup. A synthetic IoT fleet (~600 devices) built by
``serum.scenarios.iot.build_iot_fleet``: device-type firmware zones (cameras,
DVRs, routers, thermostats, bulbs, ...), each type carrying its own set of
firmware CVEs, over an ``rgg`` mesh (physical-proximity model). A Mirai-style
payload targets the default-telnet-credentials CVE (index 0), which spans
camera / DVR / router / hub in the default catalog.

Two metrics matter here:
  * ``infected_fraction`` -- how many devices got recruited.
  * ``blast_radius``      -- fraction of *DDoS bandwidth* (Mbps) conscripted.
    This is the operational quantity: a botnet of ten routers can outshoot
    a botnet of a thousand smart bulbs. SERUM's blast_radius maps directly
    onto this because ``value`` = device bandwidth on the fleet.

Policies compared (paired across the same fleet + payload + spread RNG):
  * ``no-defense``          (lower bound)
  * ``degree``              (topology-only)
  * ``content-aware``       (belief-weighted, value-blind)
  * ``content-aware+value`` (belief-weighted, DDoS-value-weighted)

Honest expectation: content-aware should reduce both metrics vs structural
baselines, and the value-weighted variant should further reduce ``blast_radius``
(DDoS capacity) at possibly a small cost on raw infected_fraction -- the same
steering trade that the enterprise ``blast_radius`` experiment showed. If it
does not, we report it truthfully.

Saves results/iot_botnet.json.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402

from serum.agents.content_aware import ContentAwareAgent  # noqa: E402
from serum.baselines.heuristics import DegreeDefense, NoDefense  # noqa: E402
from serum.scenarios.iot import build_iot_fleet, mirai_payload  # noqa: E402
from serum.sim.environment import ContainmentEnv  # noqa: E402


POLICIES = {
    "no-defense": lambda g: NoDefense(),
    "degree": lambda g: DegreeDefense(),
    "content-aware": lambda g: ContentAwareAgent(g, value_weighted=False),
    "content-aware+value": lambda g: ContentAwareAgent(g, value_weighted=True),
}


def run_one_trial(seed: int, n: int, budget_per_step: int, horizon: int,
                  n_seeds: int, target_cve: int) -> dict:
    """Build one IoT outbreak, then replay it under every policy."""
    fleet_rng = np.random.default_rng(seed)
    fleet = build_iot_fleet(n=n, topology="rgg", rng=fleet_rng)
    payload = mirai_payload(fleet, cve=target_cve)

    # Seed the outbreak on devices that actually carry the Mirai CVE (else
    # patient zero cannot spread at all). Draw from a distinct RNG so seed
    # choice is stable across policies.
    carriers = [v for v, d in fleet.g.nodes(data=True) if payload.cve in d["vuln"]]
    if len(carriers) < n_seeds:
        raise RuntimeError(
            f"IoT fleet has only {len(carriers)} carriers for cve={target_cve}; "
            f"needed {n_seeds}. Check the device catalog."
        )
    seed_rng = np.random.default_rng(seed + 42)
    seeds = [int(v) for v in seed_rng.choice(carriers, size=n_seeds, replace=False)]

    out: dict = {}
    for name, make in POLICIES.items():
        env = ContainmentEnv(
            g=fleet.g,
            payload=payload,
            seeds=seeds,
            budget_per_step=budget_per_step,
            horizon=horizon,
            # shared dynamics RNG per policy: identical infection coin-flips
            rng=np.random.default_rng(seed + 10_000_019),
        )
        res = env.run(make(env.g))
        out[name] = {
            "infected_fraction": res.infected_fraction,
            "blast_radius": res.blast_radius,
            "availability": res.availability,
        }
    # Diagnostic: fleet-level composition (device-type share of DDoS capacity).
    cap_by_type: dict = {}
    for v, d in fleet.g.nodes(data=True):
        cap_by_type.setdefault(d["device_type"], 0.0)
        cap_by_type[d["device_type"]] += d["value"]
    out["_fleet"] = {
        "n_nodes": fleet.g.number_of_nodes(),
        "n_edges": fleet.g.number_of_edges(),
        "n_carriers": len(carriers),
        "carrier_share": len(carriers) / fleet.g.number_of_nodes(),
        "capacity_by_type": {k: float(v) for k, v in cap_by_type.items()},
    }
    return out


def summarize(rows: list[dict]) -> dict:
    """Aggregate per-policy means + std errors across trials."""
    policies = [k for k in rows[0] if not k.startswith("_")]
    metrics = list(rows[0][policies[0]].keys())
    summary: dict = {}
    for p in policies:
        summary[p] = {}
        for m in metrics:
            xs = np.array([r[p][m] for r in rows], dtype=float)
            summary[p][m] = {
                "mean": float(xs.mean()),
                "se": float(xs.std(ddof=1) / np.sqrt(len(xs))) if len(xs) > 1 else 0.0,
            }
    return summary


def paired_delta(rows: list[dict], policy_a: str, policy_b: str, metric: str,
                 boot_seed: int = 0) -> dict:
    """Paired mean difference (a - b) with a bootstrap 95% CI."""
    a = np.array([r[policy_a][metric] for r in rows], dtype=float)
    b = np.array([r[policy_b][metric] for r in rows], dtype=float)
    diff = a - b
    rng = np.random.default_rng(boot_seed)
    idx = np.arange(len(diff))
    boots = np.array([
        diff[rng.choice(idx, size=len(idx), replace=True)].mean()
        for _ in range(2000)
    ])
    lo, hi = np.percentile(boots, [2.5, 97.5])
    return {
        "mean": float(diff.mean()),
        "ci95": (float(lo), float(hi)),
        "wins_a_lower": int((diff < 0).sum()),  # smaller is better on these metrics
        "n": int(len(diff)),
    }


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    n = 600
    budget_per_step = 3
    horizon = 25
    n_seeds = 5
    target_cve = 0  # Mirai flagship: default telnet credentials

    print(f"[IoT-botnet: {trials} paired trials on n={n} rgg fleets, "
          f"target=default-telnet-creds (cve=0)]")
    rows = [run_one_trial(seed=s, n=n, budget_per_step=budget_per_step,
                          horizon=horizon, n_seeds=n_seeds,
                          target_cve=target_cve)
            for s in range(trials)]
    for s in range(0, trials, 5):
        pass  # (progress printing kept lightweight)
    summary = summarize(rows)

    # Report block. Header lines echo what the columns are so a re-reader
    # doesn't have to jump back to the code to interpret them.
    print()
    header = f"{'policy':>22} {'inf%':>7} {'blast%':>8} {'avail%':>7}"
    print(header)
    print("-" * len(header))
    for p in ["no-defense", "degree", "content-aware", "content-aware+value"]:
        s = summary[p]
        print(f"{p:>22} "
              f"{100*s['infected_fraction']['mean']:>6.2f} "
              f"{100*s['blast_radius']['mean']:>7.2f} "
              f"{100*s['availability']['mean']:>6.2f}")

    # Paired effects. Two comparators that matter for the IoT thesis:
    #   (a) content-aware vs degree (does content-awareness help at all?)
    #   (b) content-aware+value vs content-aware (does value-steering help on
    #       DDoS blast radius specifically?)
    ca_vs_degree = paired_delta(rows, "content-aware", "degree",
                                "blast_radius")
    steer_blast = paired_delta(rows, "content-aware+value", "content-aware",
                               "blast_radius")
    steer_inf = paired_delta(rows, "content-aware+value", "content-aware",
                             "infected_fraction")

    print()
    print("[paired] content-aware - degree (lower blast = better)")
    print(f"  blast_radius delta:      mean={100*ca_vs_degree['mean']:+.2f}%  "
          f"ci95=({100*ca_vs_degree['ci95'][0]:+.2f}%, "
          f"{100*ca_vs_degree['ci95'][1]:+.2f}%)  "
          f"wins={ca_vs_degree['wins_a_lower']}/{ca_vs_degree['n']}")

    print("[paired] content-aware+value - content-aware  (lower blast = better)")
    print(f"  blast_radius delta:      mean={100*steer_blast['mean']:+.2f}%  "
          f"ci95=({100*steer_blast['ci95'][0]:+.2f}%, "
          f"{100*steer_blast['ci95'][1]:+.2f}%)  "
          f"wins={steer_blast['wins_a_lower']}/{steer_blast['n']}")
    print(f"  infected_fraction delta: mean={100*steer_inf['mean']:+.2f}%  "
          f"ci95=({100*steer_inf['ci95'][0]:+.2f}%, "
          f"{100*steer_inf['ci95'][1]:+.2f}%)  "
          f"wins={steer_inf['wins_a_lower']}/{steer_inf['n']}")

    os.makedirs("results", exist_ok=True)
    with open("results/iot_botnet.json", "w") as f:
        json.dump({
            "spec": {
                "scenario": "iot-mirai",
                "n": n, "topology": "rgg", "budget_per_step": budget_per_step,
                "horizon": horizon, "n_seeds": n_seeds,
                "target_cve": target_cve, "trials": trials,
            },
            "summary": summary,
            "paired_content_aware_vs_degree_blast": ca_vs_degree,
            "paired_steer_blast": steer_blast,
            "paired_steer_infected": steer_inf,
            "rows": rows,
        }, f, indent=2)
    print("\n[saved -> results/iot_botnet.json]")


if __name__ == "__main__":
    main()
