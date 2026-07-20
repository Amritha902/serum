#!/usr/bin/env python
"""Reproduce every artifact under ``results/`` from scratch.

Runs the SERUM experiment scripts in dependency order and verifies that each
declared output file was produced. Every experiment listed here is called with
the SAME defaults that generated the checked-in artifacts — so a clean run of
``python scripts/reproduce_all.py`` (given ``data/clean/cves.csv`` from
``scripts/ingest_nvd.py``) reconstructs every ``results/*.json`` and
``results/*.png`` a bit-perfect experiment at a time. The ``tests/
test_paper_claims.py`` gate then re-validates that every paper number matches
its regenerated artifact.

Usage:
    # dry run — print the plan, do nothing
    python scripts/reproduce_all.py --dry-run

    # regenerate only the cheap experiments (skip anything tagged 'slow')
    python scripts/reproduce_all.py --fast

    # regenerate a specific experiment (may be repeated)
    python scripts/reproduce_all.py --only diversity --only confusability

    # skip an experiment
    python scripts/reproduce_all.py --skip sweep --skip run_experiment

    # verify existing outputs without running anything
    python scripts/reproduce_all.py --verify

Exit code is non-zero if any experiment failed or its declared outputs are
missing after it ran.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import List

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "scripts")
RESULTS = os.path.join(ROOT, "results")


@dataclass(frozen=True)
class Experiment:
    """A single reproducible experiment.

    ``script`` is the file under ``scripts/`` (no path); ``args`` extends the
    invocation (defaults for each script were chosen to match the checked-in
    ``results/`` artifacts, so pass nothing extra unless you know why).
    ``outputs`` are paths (relative to ``results/``) that MUST exist after the
    script returns. ``tags`` classify by cost: ``fast`` (< ~1 min), ``medium``
    (~1–10 min), ``slow`` (> 10 min), ``very_slow`` (hours). ``needs`` names
    other experiments that must run first (dependency edges).
    """

    name: str
    script: str
    outputs: tuple = ()
    args: tuple = ()
    tags: frozenset = frozenset()
    needs: tuple = ()
    note: str = ""


# ---------------------------------------------------------------------------
# The reproduction manifest. Ordering is cheap -> expensive within each layer,
# and analyze_sweep depends on sweep.
# ---------------------------------------------------------------------------
MANIFEST: List[Experiment] = [
    # -- theory / identifiability -------------------------------------------
    Experiment(
        name="identifiability",
        script="identifiability.py",
        outputs=(),
        tags=frozenset({"fast"}),
        note="Empirical validation of the identifiability theorem (prints only).",
    ),
    Experiment(
        name="duality",
        script="duality.py",
        outputs=("duality.json", "duality.png"),
        tags=frozenset({"fast"}),
    ),
    # -- attribution / inference micro-experiments --------------------------
    Experiment(
        name="probing",
        script="probing.py",
        outputs=("probing.json",),
        tags=frozenset({"medium"}),
    ),
    Experiment(
        name="cold_start",
        script="cold_start.py",
        outputs=("cold_start.json",),
        tags=frozenset({"medium"}),
    ),
    Experiment(
        name="adversarial",
        script="adversarial.py",
        outputs=("adversarial.json",),
        tags=frozenset({"medium"}),
    ),
    Experiment(
        name="robust",
        script="robust.py",
        # robust.py *does* write results/robust.json, but the artifact is not
        # currently checked in (paper doesn't cite it — the BACKLOG item was
        # about landing the AGENT, not the numbers). Leaving outputs=() so
        # `--verify` doesn't flag a missing file today; if the artifact is
        # ever committed, promote it to outputs=("robust.json",).
        outputs=(),
        tags=frozenset({"medium"}),
        note="Poison-robust defender vs belief poisoning.",
    ),
    # -- containment headline & pareto --------------------------------------
    Experiment(
        name="run_experiment",
        script="run_experiment.py",
        outputs=("summary.json", "infection_curves.png"),
        tags=frozenset({"medium"}),
    ),
    Experiment(
        name="pareto",
        script="pareto.py",
        outputs=("pareto.json", "pareto.png"),
        tags=frozenset({"medium"}),
    ),
    Experiment(
        name="prevalence_curve",
        script="prevalence_curve.py",
        outputs=("prevalence_curve.json", "prevalence_curve.png"),
        tags=frozenset({"medium"}),
    ),
    # -- extended results (each is paper-claimed via test_paper_claims) -----
    Experiment(
        name="sample_complexity",
        script="sample_complexity.py",
        outputs=("sample_complexity.json", "sample_complexity.png"),
        tags=frozenset({"medium"}),
    ),
    Experiment(
        name="confusability",
        script="confusability.py",
        outputs=("confusability.json", "confusability.png"),
        tags=frozenset({"medium"}),
    ),
    Experiment(
        name="multi_exploit",
        script="multi_exploit.py",
        outputs=("multi_exploit.json", "multi_exploit.png"),
        tags=frozenset({"medium"}),
    ),
    Experiment(
        name="diversity",
        script="diversity.py",
        outputs=("diversity.json", "diversity.png"),
        tags=frozenset({"medium"}),
    ),
    Experiment(
        name="optimal_stopping",
        script="optimal_stopping.py",
        outputs=("optimal_stopping.json", "optimal_stopping.png"),
        tags=frozenset({"medium"}),
    ),
    Experiment(
        name="blast_radius",
        script="blast_radius.py",
        outputs=("blast_radius.json",),
        tags=frozenset({"medium"}),
    ),
    Experiment(
        name="iot_botnet",
        script="iot_botnet.py",
        outputs=("iot_botnet.json",),
        tags=frozenset({"medium"}),
    ),
    # -- learned policy + sweep (expensive) ---------------------------------
    Experiment(
        name="train_policy",
        script="train_policy.py",
        outputs=("policy.json",),
        tags=frozenset({"slow"}),
    ),
    Experiment(
        name="sweep",
        script="sweep.py",
        outputs=("sweep.jsonl",),
        tags=frozenset({"very_slow"}),
        note="Overnight parameter sweep — built to run for hours.",
    ),
    Experiment(
        name="analyze_sweep",
        script="analyze_sweep.py",
        outputs=("phase_diagram.png",),
        needs=("sweep",),
        tags=frozenset({"fast"}),
    ),
]


def by_name(experiments):
    d = {}
    for e in experiments:
        if e.name in d:
            raise ValueError(f"duplicate experiment name: {e.name}")
        d[e.name] = e
    return d


MANIFEST_BY_NAME = by_name(MANIFEST)


def declared_outputs():
    """All output paths declared by the manifest, deduped, path-relative to results/."""
    seen = set()
    for e in MANIFEST:
        for o in e.outputs:
            seen.add(o)
    return sorted(seen)


def missing_from_manifest(results_dir: str = RESULTS):
    """Return checked-in results artifacts that no manifest entry claims to produce.

    Skips directories (e.g. `results/ralph`, `results/real`) and non-artifact
    files (sweep.log is an incidental sidecar).
    """
    declared = set(declared_outputs())
    ignore = {"sweep.log"}
    missing = []
    if not os.path.isdir(results_dir):
        return missing
    for name in sorted(os.listdir(results_dir)):
        p = os.path.join(results_dir, name)
        if os.path.isdir(p):
            continue
        if name in ignore:
            continue
        if not (name.endswith(".json") or name.endswith(".jsonl") or name.endswith(".png")):
            continue
        if name not in declared:
            missing.append(name)
    return missing


def outputs_present(exp: Experiment, results_dir: str = RESULTS):
    return [o for o in exp.outputs if os.path.isfile(os.path.join(results_dir, o))]


def outputs_absent(exp: Experiment, results_dir: str = RESULTS):
    return [o for o in exp.outputs if not os.path.isfile(os.path.join(results_dir, o))]


def resolve_order(picked):
    """Insert dependency `needs` predecessors ahead of each experiment.

    Preserves manifest order otherwise. Raises on unknown names.
    """
    order = []
    seen = set()

    def visit(name):
        if name in seen:
            return
        if name not in MANIFEST_BY_NAME:
            raise KeyError(name)
        for pred in MANIFEST_BY_NAME[name].needs:
            visit(pred)
        seen.add(name)
        order.append(name)

    for e in MANIFEST:
        if e.name in picked:
            visit(e.name)
    return [MANIFEST_BY_NAME[n] for n in order]


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--only", action="append", default=[],
                    help="run only the named experiments (may be repeated)")
    ap.add_argument("--skip", action="append", default=[],
                    help="skip the named experiments (may be repeated)")
    ap.add_argument("--fast", action="store_true",
                    help="skip anything tagged 'slow' or 'very_slow'")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the plan; run nothing")
    ap.add_argument("--verify", action="store_true",
                    help="check that declared outputs exist on disk; run nothing")
    ap.add_argument("--continue-on-error", action="store_true",
                    help="do not abort the run if one experiment fails")
    ap.add_argument("--python", default=sys.executable,
                    help="python interpreter to invoke each experiment with")
    return ap.parse_args(argv)


def select(args):
    """Pick experiments per CLI flags.

    Dependencies are enforced in two directions:
      * ``--only`` pulls in a predecessor even if not named (in :func:`resolve_order`).
      * ``--skip`` / ``--fast`` also drop anything that transitively depends on a
        dropped experiment (a downstream analysis is meaningless without its
        upstream data).
    """
    picked = set(e.name for e in MANIFEST)
    if args.only:
        picked = {n for n in args.only}
        unknown = picked - set(MANIFEST_BY_NAME)
        if unknown:
            raise SystemExit(f"unknown --only names: {sorted(unknown)}")
    for n in args.skip:
        picked.discard(n)
    if args.fast:
        picked = {
            n for n in picked
            if not (MANIFEST_BY_NAME[n].tags & {"slow", "very_slow"})
        }

    # Drop anything whose predecessors were removed (avoid running an analysis
    # without its inputs).
    changed = True
    while changed:
        changed = False
        for n in list(picked):
            for pred in MANIFEST_BY_NAME[n].needs:
                if pred not in picked and n not in (args.only or []):
                    picked.discard(n)
                    changed = True
                    break
    return picked


def print_plan(experiments):
    print(f"[reproduce_all] {len(experiments)} experiments planned:")
    for e in experiments:
        tag = ",".join(sorted(e.tags)) or "-"
        out = " ".join(e.outputs) if e.outputs else "(stdout only)"
        print(f"  - {e.name:<20} [{tag:<10}]  -> {out}")


def run_one(exp: Experiment, python_bin: str) -> dict:
    cmd = [python_bin, os.path.join(SCRIPTS, exp.script), *exp.args]
    t0 = time.monotonic()
    print(f"\n[reproduce_all] === {exp.name}: {' '.join(cmd)} ===")
    proc = subprocess.run(cmd, cwd=ROOT)
    dt = time.monotonic() - t0
    missing = outputs_absent(exp)
    ok = proc.returncode == 0 and not missing
    status = "ok" if ok else "FAIL"
    print(f"[reproduce_all] {exp.name}: {status} in {dt:.1f}s "
          f"(rc={proc.returncode}, missing={missing})")
    return {"name": exp.name, "returncode": proc.returncode, "seconds": dt,
            "missing": missing, "ok": ok}


def do_verify(experiments):
    all_ok = True
    for e in experiments:
        if not e.outputs:
            continue
        missing = outputs_absent(e)
        status = "ok" if not missing else "MISSING"
        print(f"  {e.name:<20} {status:<8} "
              f"{'' if not missing else '(' + ', '.join(missing) + ')'}")
        if missing:
            all_ok = False
    orphans = missing_from_manifest()
    if orphans:
        print("\nOrphan results/ files (no manifest entry produces them):")
        for o in orphans:
            print(f"  - {o}")
    return all_ok


def main(argv=None) -> int:
    args = parse_args(argv)
    picked = select(args)
    experiments = resolve_order(picked)

    if args.verify:
        print(f"[reproduce_all] verifying {len(experiments)} experiments' outputs:")
        return 0 if do_verify(experiments) else 1

    print_plan(experiments)
    if args.dry_run:
        return 0

    os.makedirs(RESULTS, exist_ok=True)
    reports = []
    for e in experiments:
        r = run_one(e, args.python)
        reports.append(r)
        if not r["ok"] and not args.continue_on_error:
            print("[reproduce_all] aborting on failure "
                  "(pass --continue-on-error to override)")
            break

    print("\n[reproduce_all] summary:")
    for r in reports:
        print(f"  {r['name']:<20} rc={r['returncode']:>2} "
              f"{r['seconds']:>6.1f}s {'ok' if r['ok'] else 'FAIL'}")
    return 0 if all(r["ok"] for r in reports) else 1


if __name__ == "__main__":
    sys.exit(main())
