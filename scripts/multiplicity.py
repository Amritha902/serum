#!/usr/bin/env python
"""SR6 — Holm-Bonferroni across the SERUM headline paired comparisons.

Collects the paired-Wilcoxon p-values that back the paper's headline claims
(one per curated JSON artifact under ``results/``), applies the Holm-Bonferroni
step-down FWER correction at alpha=0.05, and writes a labelled table to
``results/multiplicity.json``. Also prints a compact markdown table to stdout so
the paper's Extended Results section stays in sync.

Design.
* Every entry maps a *label* → an already-computed paired-Wilcoxon p-value
  produced by the corresponding experiment script. No re-running of experiments,
  no re-computation of test statistics: this pass is purely a multiplicity
  correction over what's already on disk.
* The curated family excludes obvious duplicates (e.g. ``adversarial.json``'s
  "band" attacker is the same underlying run as ``multitopo.json``'s "ba" —
  identical p; keeping both would double-count and inflate the correction).
* Bonferroni is reported alongside Holm as the always-more-conservative bound.

Usage:
    python scripts/multiplicity.py                    # write results/multiplicity.json
    python scripts/multiplicity.py --alpha 0.01       # tighter FWER level
    python scripts/multiplicity.py --dry-run          # print, don't save
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from serum.inference.multiplicity import bonferroni, holm_bonferroni  # noqa: E402


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, "results")


def _read_json(path: str) -> Optional[dict]:
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        return json.load(f)


def collect_family(results_dir: str = RESULTS) -> list[dict]:
    """Extract the labelled headline paired-Wilcoxon p-values.

    Each entry is ``{"label": ..., "p_raw": ..., "source": ...}`` where
    ``source`` names the JSON path and JSON pointer so the table can be
    audited by a reviewer without re-running anything. Silently skips
    artifacts that are not on disk (e.g. a cleaner checkout).
    """
    family: list[dict] = []

    def add(label: str, p: float, source: str) -> None:
        family.append({"label": label, "p_raw": float(p), "source": source})

    # --- Synthetic real-CVE flagship (n=60 paired outbreaks) --------------
    real_sum = _read_json(os.path.join(results_dir, "real", "summary.json"))
    if real_sum is not None:
        pr = real_sum["_paired_report"]
        add("synth-flagship: content-aware vs best-fixed baseline",
            pr["primary"]["p_value"], "results/real/summary.json:primary")
        add("synth-flagship: content-aware vs ensemble oracle",
            pr["ensemble"]["p_value"], "results/real/summary.json:ensemble")

    # --- SNAP topologies (email-Eu-core, AS) ------------------------------
    snap = _read_json(os.path.join(results_dir, "real", "snap_topologies.json"))
    if snap is not None:
        topos = snap.get("topologies", {})
        for topo, pretty in (("email", "SNAP email-Eu-core"),
                             ("as", "SNAP autonomous-systems")):
            entry = topos.get(topo)
            if not entry:
                continue
            rep = entry["paired_report"]
            add(f"{pretty}: content-aware vs best-fixed baseline",
                rep["primary"]["p_value"],
                f"results/real/snap_topologies.json:topologies.{topo}.primary")
            add(f"{pretty}: content-aware vs ensemble oracle",
                rep["ensemble"]["p_value"],
                f"results/real/snap_topologies.json:topologies.{topo}.ensemble")

    # --- Synthetic topology sweep (BA, WS, RGG) ---------------------------
    # NOTE: multitopo.json's BA entry is the SAME underlying run as
    # adversarial.json's "band" attacker (identical p, prev_band, seeds); to
    # avoid double-counting we keep multitopo's BA/WS/RGG and drop
    # adversarial's "band" below.
    multitopo = _read_json(os.path.join(results_dir, "real", "multitopo.json"))
    if multitopo is not None:
        for topo, pretty in (("ba", "BA topology"), ("ws", "WS topology"),
                             ("rgg", "RGG topology")):
            entry = multitopo.get(topo)
            if not entry:
                continue
            add(f"synth {pretty}: content-aware vs best-fixed baseline",
                entry["p"], f"results/real/multitopo.json:{topo}")

    # --- Adversarial attackers (identifiable, evasive) --------------------
    adv = _read_json(os.path.join(results_dir, "adversarial.json"))
    if adv is not None:
        # Skip "band" (duplicate of multitopo.ba); keep the two distinct
        # attacker regimes that add scientific information.
        for entry in adv:
            attacker = entry.get("attacker")
            if attacker == "band":
                continue
            add(f"adversarial ({attacker}): content-aware vs best-fixed",
                entry["p"], f"results/adversarial.json:attacker={attacker}")

    return family


def format_markdown_table(rows_raw, rows_holm, rows_bonf, alpha: float) -> str:
    lines = [
        f"| # | comparison | raw p | Holm-adj p | Bonf-adj p | reject @ α={alpha:g} |",
        "|---|---|---|---|---|---|",
    ]
    # Present in ascending raw p for readability.
    order = sorted(range(len(rows_raw)),
                   key=lambda i: rows_holm[i].p_raw)
    for k, i in enumerate(order, start=1):
        h = rows_holm[i]
        b = rows_bonf[i]
        reject = "**yes**" if h.rejected else "no"
        lines.append(
            f"| {k} | {h.label} | {h.p_raw:.2e} | {h.p_adj:.2e} | "
            f"{b.p_adj:.2e} | {reject} |"
        )
    return "\n".join(lines)


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--alpha", type=float, default=0.05,
                    help="FWER level for the reject flag (default 0.05)")
    ap.add_argument("--out", default=os.path.join(RESULTS, "multiplicity.json"))
    ap.add_argument("--dry-run", action="store_true",
                    help="print table, do not write the JSON artifact")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    family = collect_family()
    if not family:
        print("[multiplicity] no headline p-values found; run the experiments first",
              file=sys.stderr)
        return 2

    pvals = [row["p_raw"] for row in family]
    labels = [row["label"] for row in family]
    sources = [row["source"] for row in family]

    holm = holm_bonferroni(pvals, labels=labels, alpha=args.alpha)
    bonf = bonferroni(pvals, labels=labels, alpha=args.alpha)

    print(f"[multiplicity] family size m = {len(family)}, alpha = {args.alpha}")
    print(format_markdown_table(family, holm, bonf, args.alpha))
    n_rej_holm = sum(1 for r in holm if r.rejected)
    n_rej_bonf = sum(1 for r in bonf if r.rejected)
    print(f"\n[multiplicity] Holm rejects {n_rej_holm}/{len(family)} "
          f"at α={args.alpha}; Bonferroni rejects {n_rej_bonf}/{len(family)}.")
    p_max_holm = max((r.p_adj for r in holm if r.rejected), default=None)
    if p_max_holm is not None:
        print(f"[multiplicity] largest Holm-adjusted p among surviving "
              f"comparisons: {p_max_holm:.4f}")

    payload = {
        "alpha": args.alpha,
        "m": len(family),
        "family": [
            {
                "label": labels[i],
                "source": sources[i],
                "p_raw": pvals[i],
                "p_holm_adj": holm[i].p_adj,
                "p_bonferroni_adj": bonf[i].p_adj,
                "rank_ascending": holm[i].rank,
                "rejected_holm": holm[i].rejected,
                "rejected_bonferroni": bonf[i].rejected,
            }
            for i in range(len(family))
        ],
        "summary": {
            "holm_rejected": n_rej_holm,
            "bonferroni_rejected": n_rej_bonf,
            "max_holm_adj_among_rejected": p_max_holm,
        },
    }

    if not args.dry_run:
        with open(args.out, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"[multiplicity] saved -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
