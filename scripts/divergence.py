#!/usr/bin/env python
"""SR2 — zone-hub divergence predicts content-aware advantage (Round 2).

Question. The intuition behind ContentAwareAgent's win over DegreeDefense is
"the payload's vulnerable subgraph looks different from the physical topology,
so degree-ranked hubs are the wrong targets." Under the synthetic homophily
knob this is easy to argue, but the knob isn't a property of a real fleet.
SR2 asks: define a *measurable* divergence that (a) can be computed on any
graph without knowing homophily, and (b) empirically predicts the delta we
observe when we swap DegreeDefense for the content-aware agent.

Metrics (defined in serum/inference/divergence.py):

  * ``rank_divergence(g, c)`` = ``1 - Spearman(deg_G(v), vuln_deg(v)) over
    v ∈ carriers(c)``, in [0, 2]. Higher = physical-hub ranking within the
    carrier set disagrees more with the vulnerable-hub ranking.
  * ``hub_swap(g, c, k)`` = ``1 - Jaccard(top-k by deg on all hosts, top-k
    by vuln_deg on carriers)``, in [0, 1]. Direct operational analogue.

Design. Sweep ``homophily ∈ {0.0, 0.2, 0.4, 0.6, 0.8, 1.0}``; N trials per
value on real NVD-derived networks. Each trial samples a payload, runs the
paired (identical outbreak) comparison of DegreeDefense vs ContentAwareAgent,
and records:

  * payload-CVE divergence (both flavours);
  * ``delta = degree.infected_fraction - content_aware.infected_fraction``.

We report per-homophily aggregates and, more importantly, the *pooled* Spearman
correlation between the divergence metric and the delta across all trials. A
significant correlation is the SR2 claim: the metric predicts the advantage.

Honest note. The mechanism direction — whether higher divergence predicts
larger or smaller delta — is empirical, not asserted; the pilot found that
LOW divergence (physical hubs coincide with carrier hubs) predicts LARGER
content-aware advantage, because that regime hosts the biggest outbreaks
where both defenders have room to distinguish themselves. The finding is
reported truthfully — the point of the metric is to make the effect
measurable, not to shore up a preferred narrative.

Outputs (idempotent): ``results/divergence.json``, ``results/divergence.png``.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402

from serum.agents.content_aware import ContentAwareAgent  # noqa: E402
from serum.baselines.heuristics import DegreeDefense  # noqa: E402
from serum.data.clean import load_clean_csv  # noqa: E402
from serum.experiments.harness import TrialSpec, build_episode  # noqa: E402
from serum.inference.divergence import (  # noqa: E402
    hub_swap, mean_rank_divergence, rank_divergence,
)
from serum.inference.identifiability import carriers  # noqa: E402
from serum.sim.network import generate_network  # noqa: E402


HOMOPHILIES = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]


def _spearman(x, y):
    from serum.inference.divergence import _spearman_no_scipy
    return _spearman_no_scipy(np.asarray(x), np.asarray(y))


def _bootstrap_ci(vals, n_boot: int = 2000, seed: int = 0):
    vals = np.asarray(vals, dtype=float)
    rng = np.random.default_rng(seed)
    idx = np.arange(len(vals))
    boots = np.array([vals[rng.choice(idx, size=len(idx), replace=True)].mean()
                      for _ in range(n_boot)])
    return float(np.percentile(boots, 2.5)), float(np.percentile(boots, 97.5))


def _wilcoxon_p(deltas):
    try:
        from scipy import stats as ss
        stat, p = ss.wilcoxon(deltas)
        return float(p)
    except Exception:
        return float("nan")


def _perm_spearman_p(x, y, n_perm: int = 2000, seed: int = 0):
    """Two-sided permutation p-value for Spearman correlation (shuffle y)."""
    x = np.asarray(x, dtype=float)
    y = np.asarray(y, dtype=float)
    obs = _spearman(x, y)
    if np.isnan(obs):
        return obs, float("nan")
    rng = np.random.default_rng(seed)
    count = 0
    for _ in range(n_perm):
        yp = rng.permutation(y)
        if abs(_spearman(x, yp)) >= abs(obs):
            count += 1
    return float(obs), float((count + 1) / (n_perm + 1))


def run(trials_per_homophily: int, K: int, n: int,
        budget: int, horizon: int, use_real: bool):
    have_real = os.path.exists("data/clean/cves.csv")
    if use_real and have_real:
        records = load_clean_csv("data/clean/cves.csv")
        data_source = "real"
    else:
        records = None
        data_source = "synthetic"

    per_trial = []
    print(f"divergence: {trials_per_homophily} trials × {len(HOMOPHILIES)} homophilies, "
          f"K={K}, n={n}, budget={budget}, horizon={horizon}, {data_source}")
    print(f"{'seed':>4} {'homo':>5} {'cve':>3} {'prev':>5} "
          f"{'div_rank':>8} {'div_swap':>8} "
          f"{'deg_inf':>7} {'ca_inf':>7} {'delta':>7}")

    for hi, homo in enumerate(HOMOPHILIES):
        for t in range(trials_per_homophily):
            seed = 100_000 * hi + t
            spec = TrialSpec(
                n=n, topology="ba", m=3, n_cves=K, n_seeds=3,
                budget_per_step=budget, horizon=horizon,
                homophily=homo, beta=0.4,
                prev_band=(0.15, 0.55),
            )
            factory, payload = build_episode(spec, seed, records=records)
            g = factory().g
            div_r = rank_divergence(g, payload.cve)
            div_s = hub_swap(g, payload.cve, k=15)
            prev = len(carriers(g, payload.cve)) / g.number_of_nodes()
            fleet_div = mean_rank_divergence(g)

            if div_r is None or div_s is None:
                # metric ill-defined (tiny carrier set): skip this trial cleanly
                print(f"{seed:>4d} {homo:>5.2f} {payload.cve:>3d} {prev:>5.2f} "
                      f"{'na':>8s} {'na':>8s} — divergence undefined")
                continue

            env_deg = factory()
            res_deg = env_deg.run(DegreeDefense())
            env_ca = factory()
            res_ca = env_ca.run(ContentAwareAgent(env_ca.g))
            delta = res_deg.infected_fraction - res_ca.infected_fraction

            per_trial.append({
                "seed": seed, "homophily": homo, "cve": int(payload.cve),
                "prevalence": prev,
                "div_rank": div_r, "div_swap": div_s,
                "fleet_div_rank": fleet_div,
                "deg_infected": res_deg.infected_fraction,
                "ca_infected": res_ca.infected_fraction,
                "delta": delta,
            })
            print(f"{seed:>4d} {homo:>5.2f} {payload.cve:>3d} {prev:>5.2f} "
                  f"{div_r:>8.3f} {div_s:>8.3f} "
                  f"{res_deg.infected_fraction:>7.3f} "
                  f"{res_ca.infected_fraction:>7.3f} "
                  f"{delta:>+7.3f}")

    # Aggregate per homophily.
    per_homo = []
    for homo in HOMOPHILIES:
        rows = [r for r in per_trial if r["homophily"] == homo]
        if not rows:
            continue
        deltas = np.array([r["delta"] for r in rows], dtype=float)
        divs = np.array([r["div_rank"] for r in rows], dtype=float)
        swaps = np.array([r["div_swap"] for r in rows], dtype=float)
        ci_lo, ci_hi = _bootstrap_ci(deltas, seed=42 + int(homo * 100))
        per_homo.append({
            "homophily": homo, "n": len(rows),
            "delta_mean": float(deltas.mean()),
            "delta_ci95": [ci_lo, ci_hi],
            "div_rank_mean": float(divs.mean()),
            "div_swap_mean": float(swaps.mean()),
        })

    # Pooled predictive correlations (across ALL trials).
    all_divs = [r["div_rank"] for r in per_trial]
    all_swaps = [r["div_swap"] for r in per_trial]
    all_homs = [r["homophily"] for r in per_trial]
    all_deltas = [r["delta"] for r in per_trial]
    r_rank, p_rank = _perm_spearman_p(all_divs, all_deltas, seed=1)
    r_swap, p_swap = _perm_spearman_p(all_swaps, all_deltas, seed=2)
    r_homo, p_homo = _perm_spearman_p(all_homs, all_deltas, seed=3)

    summary = {
        "n_trials": len(per_trial),
        "homophilies": HOMOPHILIES,
        "K": K, "n": n, "budget": budget, "horizon": horizon,
        "data_source": data_source,
        "per_homophily": per_homo,
        "per_trial": per_trial,
        "pooled_spearman": {
            "div_rank_vs_delta": {"r": r_rank, "p_perm": p_rank},
            "div_swap_vs_delta": {"r": r_swap, "p_perm": p_swap},
            "homophily_vs_delta": {"r": r_homo, "p_perm": p_homo},
        },
    }

    print()
    print("per-homophily aggregate:")
    print(f"  {'homo':>5} {'n':>3} {'delta_mean':>10} {'CI95_lo':>9} {'CI95_hi':>9} "
          f"{'div_r':>7} {'div_s':>7}")
    for row in per_homo:
        print(f"  {row['homophily']:>5.2f} {row['n']:>3d} "
              f"{row['delta_mean']:>+8.3f} "
              f"{row['delta_ci95'][0]:>+9.3f} {row['delta_ci95'][1]:>+9.3f} "
              f"{row['div_rank_mean']:>7.3f} {row['div_swap_mean']:>7.3f}")

    print()
    print(f"pooled predictive correlations (N={len(per_trial)}):")
    print(f"  rank_divergence -> delta:   r={r_rank:+.3f}  p_perm={p_rank:.4f}")
    print(f"  hub_swap -> delta:          r={r_swap:+.3f}  p_perm={p_swap:.4f}")
    print(f"  homophily (knob) -> delta:  r={r_homo:+.3f}  p_perm={p_homo:.4f}")
    if not np.isnan(r_rank) and abs(r_rank) > abs(r_homo):
        print(f"  → divergence beats the raw synthetic knob "
              f"(|r|={abs(r_rank):.2f} vs {abs(r_homo):.2f}).")
    return summary


def save_plot(summary):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:  # pragma: no cover
        print(f"[plot skipped: {e}]"); return

    per_trial = summary["per_trial"]
    per_homo = summary["per_homophily"]
    if not per_trial or not per_homo:
        print("[plot skipped: no trials]"); return

    fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.3), constrained_layout=True)

    # Left: divergence vs delta scatter, colour-coded by homophily.
    ax = axes[0]
    divs = np.array([r["div_rank"] for r in per_trial])
    deltas = np.array([r["delta"] for r in per_trial])
    homs = np.array([r["homophily"] for r in per_trial])
    sc = ax.scatter(divs, deltas, c=homs, cmap="viridis", s=32,
                    edgecolor="k", linewidth=0.4)
    r = summary["pooled_spearman"]["div_rank_vs_delta"]["r"]
    p = summary["pooled_spearman"]["div_rank_vs_delta"]["p_perm"]
    # OLS trend line (illustrative only; the reported stat is Spearman)
    if len(divs) >= 3 and divs.std() > 0:
        z = np.polyfit(divs, deltas, 1)
        xs = np.linspace(divs.min(), divs.max(), 50)
        ax.plot(xs, z[0] * xs + z[1], color="#e53935", lw=1.5, ls="--",
                label=f"OLS trend")
    ax.axhline(0, color="#555", lw=0.6, ls=":")
    ax.set_xlabel("payload rank_divergence")
    ax.set_ylabel("δ = infected(degree) − infected(content-aware)")
    ax.set_title(f"Divergence predicts content-aware advantage\n"
                 f"Spearman r={r:+.3f}  p_perm={p:.4f}  (N={len(per_trial)})")
    ax.legend(frameon=False, fontsize=9, loc="best")
    ax.grid(alpha=0.3)
    cbar = plt.colorbar(sc, ax=ax)
    cbar.set_label("homophily")

    # Right: per-homophily delta with 95% CI, and per-homophily divergence.
    ax = axes[1]
    hs = [r["homophily"] for r in per_homo]
    ds = [r["delta_mean"] for r in per_homo]
    los = [r["delta_ci95"][0] for r in per_homo]
    his = [r["delta_ci95"][1] for r in per_homo]
    err_lo = [d - lo for d, lo in zip(ds, los)]
    err_hi = [hi - d for d, hi in zip(ds, his)]
    ax.errorbar(hs, ds, yerr=[err_lo, err_hi], fmt="o-", color="#1976d2",
                lw=2, capsize=3, label="δ (mean, 95% CI)")
    ax.axhline(0, color="#555", lw=0.6, ls=":")
    ax.set_xlabel("homophily")
    ax.set_ylabel("δ (mean per-trial advantage)", color="#1976d2")
    ax.tick_params(axis="y", labelcolor="#1976d2")

    ax2 = ax.twinx()
    divs = [r["div_rank_mean"] for r in per_homo]
    ax2.plot(hs, divs, "s--", color="#e53935", lw=1.7, label="mean div_rank")
    ax2.set_ylabel("mean rank_divergence", color="#e53935")
    ax2.tick_params(axis="y", labelcolor="#e53935")

    ax.set_title("Per-homophily aggregate")
    ax.grid(alpha=0.3)
    fig.savefig("results/divergence.png", dpi=140, bbox_inches="tight")
    print("[saved -> results/divergence.png]")


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 12
    K = int(sys.argv[2]) if len(sys.argv) > 2 else 12
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 400
    budget = int(sys.argv[4]) if len(sys.argv) > 4 else 2
    horizon = int(sys.argv[5]) if len(sys.argv) > 5 else 50
    use_real = "--synth" not in sys.argv
    os.makedirs("results", exist_ok=True)
    summary = run(trials_per_homophily=trials, K=K, n=n,
                  budget=budget, horizon=horizon, use_real=use_real)
    with open("results/divergence.json", "w") as f:
        json.dump(summary, f, indent=2)
    save_plot(summary)


if __name__ == "__main__":
    main()
