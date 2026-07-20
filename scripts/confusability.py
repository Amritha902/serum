#!/usr/bin/env python
"""Confusability-graph analysis (P1).

The confusability graph on CVEs
(``serum.inference.identifiability.confusability_graph``) is a directed graph
whose edge c -> c' encodes ``carriers(c) subset carriers(c')`` — every host
vulnerable to c is also vulnerable to c'. This is exactly the subset partial
order on carrier sets, and it is the *global* ambiguity structure of the fleet:
a CVE with no out-edges is globally identifiable (no other CVE dominates it),
so a saturating outbreak of it uniquely reveals its identity.

Complementarily, per CVE, ``confusers(g, c)`` returns the residual CVEs still
consistent after a saturating outbreak on c's *largest reachable* vulnerable
component. This is the operational sample-complexity notion of ambiguity, and
it is at least as tight as the global one (the reachable component is a subset
of all carriers, so its support is a superset of the global support).

This experiment reports, on real NVD-derived networks:

  1. **Confuser-count distribution** — histogram of ``|confusers(c)|`` across
     every live CVE aggregated over many networks. Shows what fraction of
     exploits are truly ambiguous, and by how much.
  2. **Identifiable fraction vs K** — as the CVE universe grows, more CVEs
     dominate each other in the subset order, so the identifiable fraction
     decays. Sweep K in {10, 20, 30, 50, 80}. Both the saturation-based and
     global (out-degree = 0) fractions are reported.
  3. **Drawn example** — the confusability DiGraph of a single ~30-CVE network.
     Nodes are coloured by prevalence, isolated (globally identifiable) nodes
     drawn small, subset-order edges drawn as arrows.

Outputs (idempotent): ``results/confusability.json``, ``results/confusability.png``.
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402
import networkx as nx  # noqa: E402

from serum.data.clean import load_clean_csv  # noqa: E402
from serum.data.profiles import generate_real_network  # noqa: E402
from serum.inference.identifiability import (  # noqa: E402
    carriers, confusability_graph, confusers, is_identifiable,
    reachable_component,
)
from serum.sim.network import generate_network  # noqa: E402


def confuser_distribution(g: nx.Graph) -> list:
    """Per live CVE: (cve, prevalence, reachable_size, n_confusers_operational,
    n_confusers_global). Operational uses ``confusers`` (saturating outbreak on
    the largest reachable component); global uses the subset-order graph's
    out-degree (# CVEs that dominate c across the whole fleet)."""
    n = g.number_of_nodes()
    K = g.graph["n_cves"]
    cg = confusability_graph(g)
    rows = []
    for c in range(K):
        car = carriers(g, c)
        if not car:
            continue
        R = reachable_component(g, c)
        rows.append({
            "cve": c,
            "prevalence": len(car) / n,
            "reachable": len(R),
            "n_confusers_op": len(confusers(g, c)),
            "n_confusers_global": int(cg.out_degree(c)),
            "identifiable_op": is_identifiable(g, c),
            "identifiable_global": bool(cg.out_degree(c) == 0),
        })
    return rows


def identifiable_fraction_sweep(records, K_values, trials, base_rng):
    """Sweep the CVE-universe size K; for each K, report both fractions."""
    out = []
    for K in K_values:
        op, glob, live_counts = [], [], []
        for t in range(trials):
            g = generate_real_network(
                records, n=400, n_cves=K, n_products=max(60, 2 * K),
                homophily=0.4, rng=np.random.default_rng(base_rng + 1000 * K + t))
            live = [c for c in range(K) if carriers(g, c)]
            if not live:
                continue
            cg = confusability_graph(g)
            op.append(sum(1 for c in live if is_identifiable(g, c)) / len(live))
            glob.append(sum(1 for c in live if cg.out_degree(c) == 0) / len(live))
            live_counts.append(len(live))
        if op:
            out.append({
                "K": K,
                "trials": len(op),
                "mean_live": float(np.mean(live_counts)),
                "identifiable_op_mean": float(np.mean(op)),
                "identifiable_op_std": float(np.std(op)),
                "identifiable_global_mean": float(np.mean(glob)),
                "identifiable_global_std": float(np.std(glob)),
            })
    return out


def pick_drawing_network(records, rng_base=0, K=30):
    """Pick a network whose confusability graph has some non-trivial edges so
    the drawing is informative (not just isolated nodes)."""
    best_g, best_cg, best_edges = None, None, -1
    for t in range(6):
        g = generate_real_network(records, n=400, n_cves=K, n_products=70,
                                  homophily=0.4, rng=np.random.default_rng(rng_base + t))
        cg = confusability_graph(g)
        if cg.number_of_edges() > best_edges:
            best_g, best_cg, best_edges = g, cg, cg.number_of_edges()
    return best_g, best_cg


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    use_real = "--synth" not in sys.argv
    have_real = os.path.exists("data/clean/cves.csv")
    if use_real and have_real:
        records = load_clean_csv("data/clean/cves.csv")
        data_source = "real"
    else:
        records = None
        data_source = "synthetic"

    os.makedirs("results", exist_ok=True)

    # --- distribution over many nets at the flagship setting ---
    K_flag = 30
    all_rows = []
    for t in range(trials):
        if records is not None:
            g = generate_real_network(records, n=400, n_cves=K_flag, n_products=70,
                                      homophily=0.4, rng=np.random.default_rng(t))
        else:
            g = generate_network(n=400, n_cves=K_flag, vuln_lambda=5,
                                 popularity_alpha=0.7, rng=np.random.default_rng(t))
        rows = confuser_distribution(g)
        for r in rows:
            r["net"] = t
        all_rows.extend(rows)

    n_live = len(all_rows)
    ops = np.array([r["n_confusers_op"] for r in all_rows])
    globs = np.array([r["n_confusers_global"] for r in all_rows])
    ident_op = float(np.mean(ops == 0)) if n_live else 0.0
    ident_glob = float(np.mean(globs == 0)) if n_live else 0.0
    op_hist = Counter(int(x) for x in ops)
    glob_hist = Counter(int(x) for x in globs)

    print(f"confusability analysis: {trials} networks, {data_source}, K={K_flag}")
    print(f"  live CVEs analysed:              {n_live}")
    print(f"  identifiable fraction (saturation): {ident_op:.3f}")
    print(f"  identifiable fraction (global):     {ident_glob:.3f}")
    print(f"  operational n_confusers (mean/med/p90): "
          f"{ops.mean():.2f} / {np.median(ops):.0f} / {np.quantile(ops, 0.9):.0f}")
    print(f"  global      n_confusers (mean/med/p90): "
          f"{globs.mean():.2f} / {np.median(globs):.0f} / {np.quantile(globs, 0.9):.0f}")

    # --- K sweep (only when we have real data — synth mode reports flag only) ---
    if records is not None:
        K_sweep = identifiable_fraction_sweep(records, [10, 20, 30, 50, 80],
                                              trials=max(3, trials // 2), base_rng=0)
        print("\n  K sweep:")
        print(f"    {'K':>3}  {'live':>5}  {'ident-sat':>10}  {'ident-global':>13}")
        for row in K_sweep:
            print(f"    {row['K']:>3}  {row['mean_live']:>5.1f}  "
                  f"{row['identifiable_op_mean']:>10.3f}  "
                  f"{row['identifiable_global_mean']:>13.3f}")
    else:
        K_sweep = []

    # --- drawn example network ---
    if records is not None:
        draw_g, draw_cg = pick_drawing_network(records)
    else:
        draw_g = generate_network(n=400, n_cves=16, vuln_lambda=5,
                                  popularity_alpha=0.7, rng=np.random.default_rng(0))
        draw_cg = confusability_graph(draw_g)

    out = {
        "trials": trials,
        "data_source": data_source,
        "K_flagship": K_flag,
        "n_live": n_live,
        "identifiable_fraction_op": ident_op,
        "identifiable_fraction_global": ident_glob,
        "n_confusers_op_hist": {int(k): int(v) for k, v in sorted(op_hist.items())},
        "n_confusers_global_hist": {int(k): int(v) for k, v in sorted(glob_hist.items())},
        "op_summary": {
            "mean": float(ops.mean()), "median": float(np.median(ops)),
            "p90": float(np.quantile(ops, 0.9)), "max": int(ops.max()),
        },
        "global_summary": {
            "mean": float(globs.mean()), "median": float(np.median(globs)),
            "p90": float(np.quantile(globs, 0.9)), "max": int(globs.max()),
        },
        "K_sweep": K_sweep,
        "per_cve": all_rows,
    }
    with open("results/confusability.json", "w") as f:
        json.dump(out, f, indent=2)
    save_plot(out, draw_g, draw_cg)


def save_plot(out, draw_g, draw_cg):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:  # pragma: no cover
        print(f"[plot skipped: {e}]"); return

    fig = plt.figure(figsize=(14, 4.6), constrained_layout=True)
    gs = fig.add_gridspec(1, 3, width_ratios=[1.0, 1.0, 1.3])

    # panel A: confuser count histograms (operational + global overlay)
    ax1 = fig.add_subplot(gs[0, 0])
    op_hist = out["n_confusers_op_hist"]
    gl_hist = out["n_confusers_global_hist"]
    max_x = max(list(op_hist) + list(gl_hist) + [0])
    xs = np.arange(max_x + 1)
    op_bars = np.array([op_hist.get(int(x), 0) for x in xs])
    gl_bars = np.array([gl_hist.get(int(x), 0) for x in xs])
    width = 0.42
    ax1.bar(xs - width / 2, op_bars, width, color="#1976d2",
            label=f"operational (saturating outbreak)\nidentifiable {out['identifiable_fraction_op']:.0%}")
    ax1.bar(xs + width / 2, gl_bars, width, color="#e53935",
            label=f"global (subset order)\nidentifiable {out['identifiable_fraction_global']:.0%}")
    ax1.set_xlabel("# residual confusers per CVE")
    ax1.set_ylabel("count (across all live CVEs, all networks)")
    ax1.set_title(f"Confuser count distribution\n(K={out['K_flagship']}, "
                  f"{out['trials']} networks, {out['n_live']} live CVEs)")
    ax1.legend(frameon=False, fontsize=8)
    ax1.grid(alpha=0.3, axis="y")

    # panel B: identifiable fraction vs K
    ax2 = fig.add_subplot(gs[0, 1])
    if out["K_sweep"]:
        Ks = [r["K"] for r in out["K_sweep"]]
        op_m = [r["identifiable_op_mean"] for r in out["K_sweep"]]
        op_s = [r["identifiable_op_std"] for r in out["K_sweep"]]
        gl_m = [r["identifiable_global_mean"] for r in out["K_sweep"]]
        gl_s = [r["identifiable_global_std"] for r in out["K_sweep"]]
        ax2.errorbar(Ks, op_m, yerr=op_s, fmt="o-", color="#1976d2",
                     capsize=3, lw=2, label="operational")
        ax2.errorbar(Ks, gl_m, yerr=gl_s, fmt="s--", color="#e53935",
                     capsize=3, lw=2, label="global")
        ax2.set_xlabel("K (CVE-universe size)")
        ax2.set_ylabel("identifiable fraction")
        ax2.set_title("Identifiability decays with K\n(more CVEs = more subset-order dominators)")
        ax2.set_ylim(0.0, 1.05)
        ax2.legend(frameon=False, fontsize=9)
        ax2.grid(alpha=0.3)
    else:
        ax2.text(0.5, 0.5, "(K sweep only in real-data mode)",
                 ha="center", va="center", transform=ax2.transAxes,
                 fontsize=10, color="#666")
        ax2.set_axis_off()

    # panel C: drawn confusability subgraph
    ax3 = fig.add_subplot(gs[0, 2])
    K = draw_g.graph["n_cves"]
    n = draw_g.number_of_nodes()
    prev = np.array([len(carriers(draw_g, c)) / n for c in range(K)])
    live = [c for c in range(K) if prev[c] > 0]
    sub = draw_cg.subgraph(live).copy()
    # separate isolated (globally-identifiable) nodes from the "confused" cluster
    connected = set()
    for u, v in sub.edges():
        connected.update((u, v))
    isolated = [c for c in live if c not in connected]

    # layout: put the connected component in the centre with spring; isolated
    # nodes in a ring on the outside so the story reads "many identifiable,
    # a smaller cluster of confusable CVEs"
    pos = {}
    if connected:
        connected_sub = sub.subgraph(connected)
        pos.update(nx.spring_layout(connected_sub, seed=0, k=0.9))
    if isolated:
        radius = 1.5
        for i, c in enumerate(sorted(isolated)):
            theta = 2 * np.pi * i / max(1, len(isolated))
            pos[c] = np.array([radius * np.cos(theta), radius * np.sin(theta)])

    sizes = 40 + 400 * prev
    # colour by prevalence
    colours = [prev[c] for c in sub.nodes()]
    node_sizes = [sizes[c] for c in sub.nodes()]
    nx.draw_networkx_nodes(sub, pos, ax=ax3, node_color=colours, cmap="viridis",
                           node_size=node_sizes, edgecolors="#333", linewidths=0.6,
                           vmin=0, vmax=max(prev) if len(prev) else 1)
    nx.draw_networkx_edges(sub, pos, ax=ax3, edge_color="#666", width=0.9,
                           arrows=True, arrowsize=8, alpha=0.7,
                           connectionstyle="arc3,rad=0.05")
    # only label the "connected" nodes to avoid clutter
    labels = {c: str(c) for c in connected}
    nx.draw_networkx_labels(sub, pos, labels, ax=ax3, font_size=7, font_color="white")

    ax3.set_title(f"Confusability graph example\n"
                  f"K={K}, {len(live)} live, {len(isolated)} globally identifiable, "
                  f"{sub.number_of_edges()} subset-order edges")
    ax3.set_axis_off()

    fig.savefig("results/confusability.png", dpi=140, bbox_inches="tight")
    print("[saved -> results/confusability.png, results/confusability.json]")


if __name__ == "__main__":
    main()
