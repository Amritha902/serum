#!/usr/bin/env python
"""Optimal stopping: when should the defender commit vs keep watching? (P2)

Setting.  There is a real trade-off between waiting for a better belief and
letting the outbreak grow:

    act early -> misspent budget under uncertainty
    act late  -> better belief but a larger frontier to contain

Whether that trade-off *bites* depends on how the defender uses its belief.
We test two act-modes:

  * ``hedge`` — the plain ContentAwareAgent, taking the score expectation
    over the full CVE posterior. This is the SERUM default.
  * ``commit`` — patch only hosts vulnerable to the current MAP CVE (no
    hedging). A single guess: right = maximal efficiency; wrong = wasted step.
    This is a classical Wald-style sequential-testing setup where the
    stopping question is real.

Design.  Every paired trial (same graph, payload, seeds, spread RNG) is faced
by three families of defender *per act-mode*:

  * ``no-stop`` — act every step from t=0.
  * ``fixed-stop-T`` — watch T steps, then delegate. Sweeping ``T`` traces
    the wait-vs-spread curve; its per-trial minimum is the *oracle* stopping
    time. A real defender does not know it.
  * ``adaptive-stop(S<=k)`` — trigger once the hard-consistency support has
    shrunk to k or fewer CVEs. No oracle knowledge, purely belief-driven.

Claim.  Under ``commit`` the adaptive rule should match or beat the
oracle-best fixed T on paired trials — matching an oracle without seeing the
future. Under ``hedge`` we expect (and honestly report) that T=0 dominates:
the posterior-expectation defender already handles CVE uncertainty at t=0,
so waiting is not rewarded. This IS the takeaway: SERUM's inference makes
optimal stopping unnecessary; a lesser defender needs it.

Outputs (idempotent):
  results/optimal_stopping.json
  results/optimal_stopping.png
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402

from serum.agents.content_aware import ContentAwareAgent  # noqa: E402
from serum.agents.stopping import AdaptiveStopAgent, FixedStopAgent  # noqa: E402
from serum.baselines.heuristics import NoDefense  # noqa: E402
from serum.experiments.harness import TrialSpec, build_episode  # noqa: E402


FIXED_TS = (0, 1, 2, 3, 5, 8, 12)
ADAPTIVE_TRIGGERS = (
    {"support_leq": 5},
    {"support_leq": 3},
    {"support_leq": 1},
)
ACT_MODES = ("hedge", "commit")


def _load_records():
    """Real NVD-derived records if the corpus is on disk, else ``None``
    (falls back to the synthetic Zipf network)."""
    try:
        from serum.data.clean import load_clean_csv
    except Exception:
        return None
    path = "data/clean/cves.csv"
    return load_clean_csv(path) if os.path.exists(path) else None


def _make_spec(records) -> TrialSpec:
    return TrialSpec(
        n=400,
        topology="ba" if records is None else "rgg",
        m=3,
        n_cves=30 if records is not None else 16,
        n_products=70,
        n_segments=8,
        homophily=0.4,
        beta=0.35,
        n_seeds=3,
        budget_per_step=5,
        horizon=30,
    )


def _run_one(factory, policy):
    env = factory()
    return env.run(policy)


def _fmt(x, w=6, p=3):
    return f"{x:>{w}.{p}f}"


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 24
    records = _load_records()
    spec = _make_spec(records)
    print(f"optimal-stopping: {trials} paired trials on "
          f"{'real NVD' if records is not None else 'synthetic'} networks "
          f"(n={spec.n}, K={spec.n_cves}, budget={spec.budget_per_step})\n")

    def policy_names_for(mode: str) -> list[str]:
        return (
            [f"no-stop.{mode}"]
            + [f"fixed-t{t}.{mode}" for t in FIXED_TS]
            + [f"adaptive-S<={cfg['support_leq']}.{mode}" for cfg in ADAPTIVE_TRIGGERS]
        )

    policy_names = ["no-defense"] + [n for m in ACT_MODES for n in policy_names_for(m)]
    inf: dict[str, list[float]] = {n: [] for n in policy_names}
    stops: dict[str, list[int | None]] = {}
    for mode in ACT_MODES:
        for cfg in ADAPTIVE_TRIGGERS:
            stops[f"adaptive-S<={cfg['support_leq']}.{mode}"] = []

    for t in range(trials):
        factory, _payload = build_episode(spec, seed=t, records=records)
        r_none = _run_one(factory, NoDefense())
        inf["no-defense"].append(r_none.infected_fraction)
        for mode in ACT_MODES:
            # (2) act every step from t=0 (in this mode)
            if mode == "hedge":
                r_ns = _run_one(factory, ContentAwareAgent(factory().g))
            else:
                r_ns = _run_one(factory,
                                FixedStopAgent(factory().g, stop_time=0, act_mode=mode))
            inf[f"no-stop.{mode}"].append(r_ns.infected_fraction)
            # (3) fixed-stop sweep
            for T in FIXED_TS:
                r = _run_one(factory,
                             FixedStopAgent(factory().g, stop_time=T, act_mode=mode))
                inf[f"fixed-t{T}.{mode}"].append(r.infected_fraction)
            # (4) adaptive-stop triggers
            for cfg in ADAPTIVE_TRIGGERS:
                ag = AdaptiveStopAgent(factory().g, min_watch=1,
                                       act_mode=mode, **cfg)
                r = _run_one(factory, ag)
                key = f"adaptive-S<={cfg['support_leq']}.{mode}"
                inf[key].append(r.infected_fraction)
                stops[key].append(ag.stop_at)
        print(f"  trial {t + 1}/{trials} done", flush=True)

    # ---- summary ------------------------------------------------------
    arr = {k: np.asarray(v, dtype=float) for k, v in inf.items()}

    reports_by_mode: dict = {}
    for mode in ACT_MODES:
        fixed_mat = np.vstack([arr[f"fixed-t{T}.{mode}"] for T in FIXED_TS])
        oracle_fixed = fixed_mat.min(axis=0)
        oracle_T = np.array(FIXED_TS)[fixed_mat.argmin(axis=0)]

        print(f"\n=== act-mode = {mode.upper()} ===")
        print("  per-policy mean infected fraction:")
        for T in FIXED_TS:
            k = f"fixed-t{T}.{mode}"
            print(f"    T={T:<3}  mean={arr[k].mean():.3f}  std={arr[k].std():.3f}")
        for cfg in ADAPTIVE_TRIGGERS:
            k = f"adaptive-S<={cfg['support_leq']}.{mode}"
            print(f"    {k:>28}  mean={arr[k].mean():.3f}  std={arr[k].std():.3f}")
        print(f"    oracle-fixed (per-trial best T)  mean={oracle_fixed.mean():.3f}")

        def _paired(name, oracle=oracle_fixed):
            ada = arr[name]
            diff = ada - oracle
            rng = np.random.default_rng(0)
            idx = np.arange(len(ada))
            boots = np.array([diff[rng.choice(idx, size=len(idx), replace=True)].mean()
                              for _ in range(5000)])
            lo, hi = np.percentile(boots, [2.5, 97.5])
            wins_or_ties = int((ada <= oracle).sum())
            return {
                "policy": name,
                "mean_infected": float(ada.mean()),
                "gap_vs_oracle_fixed": float(diff.mean()),
                "ci95_gap": (float(lo), float(hi)),
                "wins_or_ties_vs_oracle_fixed": wins_or_ties,
            }

        mode_reports = {}
        print("  paired vs oracle-fixed:")
        for cfg in ADAPTIVE_TRIGGERS:
            name = f"adaptive-S<={cfg['support_leq']}.{mode}"
            rep = _paired(name)
            mode_reports[name] = rep
            lo, hi = rep["ci95_gap"]
            print(f"    {name:>28}  Δ={rep['gap_vs_oracle_fixed']:+.3f}  "
                  f"CI95 [{lo:+.3f}, {hi:+.3f}]  "
                  f"wins/ties {rep['wins_or_ties_vs_oracle_fixed']}/{trials}")
        print("  oracle T distribution:")
        unique, counts = np.unique(oracle_T, return_counts=True)
        for T, n in zip(unique, counts):
            print(f"    T={int(T):<3}  {n}/{trials}")
        reports_by_mode[mode] = {
            "oracle_fixed_per_trial": oracle_fixed.tolist(),
            "oracle_T_per_trial": oracle_T.tolist(),
            "oracle_fixed_mean": float(oracle_fixed.mean()),
            "adaptive_report": mode_reports,
        }

    # ---- save --------------------------------------------------------
    os.makedirs("results", exist_ok=True)
    out = {
        "trials": trials,
        "data_source": "real" if records is not None else "synthetic",
        "spec": {k: getattr(spec, k) for k in
                 ("n", "topology", "n_cves", "beta", "n_seeds",
                  "budget_per_step", "horizon", "homophily")},
        "fixed_ts": list(FIXED_TS),
        "adaptive_triggers": [c for c in ADAPTIVE_TRIGGERS],
        "act_modes": list(ACT_MODES),
        "per_policy_infected": {k: v.tolist() for k, v in arr.items()},
        "adaptive_stop_times": {k: v for k, v in stops.items()},
        "reports_by_mode": reports_by_mode,
        "means": {k: float(v.mean()) for k, v in arr.items()},
    }
    with open("results/optimal_stopping.json", "w") as f:
        json.dump(out, f, indent=2)
    save_plot(out)


def save_plot(out):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:  # pragma: no cover
        print(f"[plot skipped: {e}]")
        return

    means = out["means"]
    Ts = out["fixed_ts"]
    modes = out["act_modes"]
    fig, axes = plt.subplots(1, len(modes) + 1, figsize=(4.6 * (len(modes) + 1), 4.4))
    ada_colors = ["#e53935", "#8e24aa", "#fb8c00"]

    for i, mode in enumerate(modes):
        ax = axes[i]
        fixed_means = [means[f"fixed-t{T}.{mode}"] for T in Ts]
        ax.plot(Ts, fixed_means, "o-", color="#1976d2", lw=2, label=f"fixed-stop T ({mode})")
        ax.axhline(means["no-defense"], ls=":", color="#616161", label="no defense")
        for j, cfg in enumerate(out["adaptive_triggers"]):
            key = f"adaptive-S<={cfg['support_leq']}.{mode}"
            ax.axhline(means[key], ls="-.", color=ada_colors[j % len(ada_colors)],
                       label=f"adaptive S≤{cfg['support_leq']} = {means[key]:.3f}")
        ora = out["reports_by_mode"][mode]["oracle_fixed_mean"]
        ax.axhline(ora, ls="-", color="#000", lw=1.2, alpha=0.6,
                   label=f"oracle-fixed = {ora:.3f}")
        ax.set_xlabel("stop time T (steps before acting)")
        ax.set_ylabel("mean infected fraction (paired trials)")
        ax.set_title(f"wait-vs-spread — act={mode}")
        ax.grid(alpha=0.3)
        ax.legend(frameon=False, fontsize=8, loc="best")

    ax = axes[-1]
    tightest = out["adaptive_triggers"][-1]
    for mode in modes:
        key = f"adaptive-S<={tightest['support_leq']}.{mode}"
        st = [s for s in out["adaptive_stop_times"][key] if s is not None]
        if st:
            ax.hist(st, bins=range(0, max(st) + 2), align="left", alpha=0.6,
                    label=f"{mode} (n={len(st)})", edgecolor="white")
    ax.set_xlabel(f"belief-driven stop time (S≤{tightest['support_leq']})")
    ax.set_ylabel("# trials")
    ax.set_title("adaptive stop-time distribution")
    ax.grid(alpha=0.3)
    ax.legend(frameon=False, fontsize=9)

    fig.tight_layout()
    fig.savefig("results/optimal_stopping.png", dpi=140)
    print("[saved -> results/optimal_stopping.png, results/optimal_stopping.json]")


if __name__ == "__main__":
    main()
