#!/usr/bin/env python
"""Sample complexity of exploit identification (P1).

How much of the outbreak does the defender have to *see* before the payload's
identity is pinned down? For every identifiable CVE on a real-data network we
run a saturating no-defense outbreak, record the posterior support size after
every step, and read off the *identification latency*: the infected fraction at
which the support first collapses to 1.

Ties to noisy group testing (Aldridge, Johnson, Scarlett 2019 survey). Here each
newly infected non-seed host is a "test" that intersects the current support
with the host's carried CVEs. With K candidate CVEs and independent per-host
profiles, an information-theoretic lower bound predicts identification requires
O(log K) informative observations. Because host profiles are *correlated* under
software monoculture (real data has products co-deployed within segments), we
expect the empirical curve to be worse than the i.i.d. bound in the tail: a
handful of "widely vulnerable" CVEs never separate from each other and drive the
mean up. Reporting the median + a survival curve keeps that honest.

Outputs (idempotent): ``results/sample_complexity.json`` and
``results/sample_complexity.png``.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402

from serum.data.clean import load_clean_csv  # noqa: E402
from serum.data.profiles import generate_real_network  # noqa: E402
from serum.inference.identifiability import (  # noqa: E402
    carriers, identification_latency, identification_trajectory,
    is_identifiable, reachable_component,
)
from serum.sim.network import generate_network  # noqa: E402


def run_one_network(g, rng: np.random.Generator, min_component: int = 10):
    """Sweep every identifiable CVE whose reachable component is large enough to
    observe, and return per-CVE identification-latency records."""
    n = g.number_of_nodes()
    n_cves = g.graph["n_cves"]
    records = []
    for c in range(n_cves):
        car = carriers(g, c)
        if not car:
            continue
        R = reachable_component(g, c)
        if len(R) < min_component:
            continue
        if not is_identifiable(g, c):
            # unidentifiable CVEs can never hit support==1; record their floor
            continue
        # small seed set inside R so the outbreak actually starts and saturates
        seeds = [int(x) for x in np.random.default_rng(1000 + c).choice(
            sorted(R), size=min(3, len(R)), replace=False)]
        traj = identification_trajectory(g, c, seeds, beta=1.0, horizon=200,
                                         rng=np.random.default_rng(int(rng.integers(1 << 30))))
        lat = identification_latency(traj, target_support=1)
        # infected fraction *within the reachable component* is the honest denom
        rec = {
            "cve": c,
            "carriers": len(car),
            "prevalence": len(car) / n,
            "reachable": len(R),
            "identified": lat is not None,
        }
        if lat is not None:
            rec.update({
                "step_id": lat["step"],
                "infected_at_id": lat["infected"],
                "infected_frac_at_id": lat["infected_frac"],
                "infected_frac_of_reach": lat["infected"] / len(R),
                "log2K_over_infected": (np.log2(n_cves) / max(1, lat["infected"])),
            })
        records.append(rec)
    return records


def summarise(records: list, n_cves: int) -> dict:
    idd = [r for r in records if r["identified"]]
    if not idd:
        return {"n_cves_probed": len(records), "identified": 0}
    fracs = np.array([r["infected_frac_at_id"] for r in idd])
    reach_fracs = np.array([r["infected_frac_of_reach"] for r in idd])
    hosts = np.array([r["infected_at_id"] for r in idd])
    return {
        "n_cves_probed": len(records),
        "identified": len(idd),
        "median_infected_frac_at_id": float(np.median(fracs)),
        "mean_infected_frac_at_id": float(np.mean(fracs)),
        "p90_infected_frac_at_id": float(np.quantile(fracs, 0.90)),
        "median_infected_frac_of_reach": float(np.median(reach_fracs)),
        "median_hosts_at_id": float(np.median(hosts)),
        "log2K_hosts_ratio_median": float(np.median(np.log2(n_cves) / np.maximum(1, hosts))),
    }


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 6
    use_real = "--synth" not in sys.argv
    have_real = os.path.exists("data/clean/cves.csv")
    if use_real and have_real:
        records = load_clean_csv("data/clean/cves.csv")
    else:
        records = None

    os.makedirs("results", exist_ok=True)
    per_cve_rows: list = []
    per_net_summaries: list = []
    print(f"sample-complexity experiment: {trials} networks, "
          f"{'real data' if records is not None else 'synthetic'}\n")
    header = f"{'net':>3}  {'#id':>4}/{'#probed':>7}  {'med host':>8}  {'med frac':>8}  {'p90 frac':>8}  {'med reach%':>10}"
    print(header)
    print("-" * len(header))
    for t in range(trials):
        rng = np.random.default_rng(t)
        if records is not None:
            g = generate_real_network(records, n=400, n_cves=30, n_products=70,
                                      homophily=0.4, rng=rng)
        else:
            g = generate_network(n=400, n_cves=16, vuln_lambda=5,
                                 popularity_alpha=0.7, rng=rng)
        recs = run_one_network(g, rng)
        for r in recs:
            r["net"] = t
        per_cve_rows.extend(recs)
        summary = summarise(recs, g.graph["n_cves"])
        summary["net"] = t
        per_net_summaries.append(summary)
        if summary.get("identified", 0) > 0:
            print(f"{t:>3}  {summary['identified']:>4}/{summary['n_cves_probed']:>7}  "
                  f"{summary['median_hosts_at_id']:>8.1f}  "
                  f"{summary['median_infected_frac_at_id']:>8.3f}  "
                  f"{summary['p90_infected_frac_at_id']:>8.3f}  "
                  f"{summary['median_infected_frac_of_reach']:>10.3f}")
        else:
            print(f"{t:>3}  {0:>4}/{summary['n_cves_probed']:>7}  "
                  f"{'-':>8}  {'-':>8}  {'-':>8}  {'-':>10}")

    idd = [r for r in per_cve_rows if r.get("identified")]
    if idd:
        all_fracs = np.array([r["infected_frac_at_id"] for r in idd])
        all_hosts = np.array([r["infected_at_id"] for r in idd])
        all_reach = np.array([r["infected_frac_of_reach"] for r in idd])
        overall = {
            "n_cves_probed": len(per_cve_rows),
            "n_identified": len(idd),
            "identification_rate": len(idd) / max(1, len(per_cve_rows)),
            "median_hosts_at_id": float(np.median(all_hosts)),
            "median_infected_frac_at_id": float(np.median(all_fracs)),
            "p90_infected_frac_at_id": float(np.quantile(all_fracs, 0.90)),
            "median_infected_frac_of_reach": float(np.median(all_reach)),
        }
        # information-theoretic sanity check: with K CVEs, an oracle needing
        # log2(K) bits of evidence should be identified after ~log2(K) infections
        # in the best case. Report the ratio of empirical hosts / log2(K).
        # A ratio > 1 means real correlated profiles are less informative than
        # i.i.d. bits, exactly what we'd expect under monoculture.
        # (`n_cves` may differ per network under real-data seeding — use the
        # first network's value as the reference K for this ratio.)
        # For real-data runs this is the same K across all networks.
        K = 30 if records is not None else 16
        overall["K_ref"] = K
        overall["log2K"] = float(np.log2(K))
        overall["empirical_hosts_over_log2K"] = float(
            np.median(all_hosts) / np.log2(K)
        )
    else:
        overall = {"n_cves_probed": len(per_cve_rows), "n_identified": 0}

    print("\n=== overall ===")
    for k, v in overall.items():
        print(f"  {k:>35}  {v}")

    out = {
        "trials": trials,
        "data_source": "real" if records is not None else "synthetic",
        "overall": overall,
        "per_network": per_net_summaries,
        "per_cve": per_cve_rows,
    }
    with open("results/sample_complexity.json", "w") as f:
        json.dump(out, f, indent=2)
    save_plot(per_cve_rows, out)


def save_plot(per_cve_rows, out):
    idd = [r for r in per_cve_rows if r.get("identified")]
    if not idd:
        print("[no identified cves -> plot skipped]")
        return
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:  # pragma: no cover
        print(f"[plot skipped: {e}]")
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.4))
    fracs = np.array(sorted(r["infected_frac_at_id"] for r in idd))
    surv = 1 - np.arange(len(fracs)) / len(fracs)
    ax1.plot(fracs, surv, lw=2.2, color="#1976d2")
    ax1.set_xlabel("infected fraction of fleet at identification")
    ax1.set_ylabel("P(not yet identified)")
    ax1.set_title("survival curve of identification latency")
    ax1.grid(alpha=0.3)

    # prevalence vs sample-complexity scatter
    prev = np.array([r["prevalence"] for r in idd])
    hosts = np.array([r["infected_at_id"] for r in idd])
    ax2.scatter(prev, hosts, alpha=0.6, s=28, color="#e53935")
    ax2.set_xlabel("target-CVE prevalence (fraction vulnerable)")
    ax2.set_ylabel("# infections observed to identify")
    ax2.set_title("sample complexity vs target prevalence")
    ax2.grid(alpha=0.3)
    if "log2K" in out.get("overall", {}):
        ax2.axhline(out["overall"]["log2K"], ls="--", color="#666",
                    label=f"log2 K = {out['overall']['log2K']:.1f} (i.i.d. bit-bound)")
        ax2.legend(frameon=False, fontsize=9)

    fig.tight_layout()
    fig.savefig("results/sample_complexity.png", dpi=140)
    print("[saved -> results/sample_complexity.png, results/sample_complexity.json]")


if __name__ == "__main__":
    main()
