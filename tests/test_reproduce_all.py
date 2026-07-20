"""Tests for the reproduce-all script.

These tests exercise the *manifest* — the declarative list of experiment scripts
and their outputs — not the reproduction itself (running every experiment takes
hours). They guard against three drift modes that would otherwise ship silently:

  1. A manifest entry naming a script that doesn't exist.
  2. A checked-in ``results/*.json`` / ``*.png`` artifact that no manifest entry
     claims to produce (orphan output).
  3. A manifest entry declaring an output that isn't already on disk (indicating
     either a busted script or a stale manifest).

We also cover the small pieces of imperative logic: CLI selection (``--only``,
``--skip``, ``--fast``) and the dependency-resolution rule.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from scripts import reproduce_all as R

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
RESULTS = ROOT / "results"


def test_every_manifest_script_exists() -> None:
    for exp in R.MANIFEST:
        p = SCRIPTS / exp.script
        assert p.is_file(), f"{exp.name} points to missing script {p}"


def test_manifest_names_are_unique() -> None:
    names = [e.name for e in R.MANIFEST]
    assert len(names) == len(set(names)), "duplicate manifest names"


def test_no_orphan_result_files() -> None:
    """Every checked-in results file must be produced by some manifest entry."""
    orphans = R.missing_from_manifest(str(RESULTS))
    assert orphans == [], (
        "results/ has files no experiment in reproduce_all.MANIFEST claims to "
        f"produce: {orphans}. Either add a manifest entry or remove the file."
    )


def test_declared_outputs_exist_on_disk() -> None:
    """Manifest claims about outputs must match what is checked in.

    If this fails after a manifest edit, either regenerate the artifact or
    remove the declaration.
    """
    for exp in R.MANIFEST:
        missing = R.outputs_absent(exp, str(RESULTS))
        assert not missing, (
            f"{exp.name} declares outputs {missing} that don't exist under "
            "results/. Run the script or fix the manifest."
        )


def test_dependencies_resolve_to_known_names() -> None:
    known = {e.name for e in R.MANIFEST}
    for exp in R.MANIFEST:
        for pred in exp.needs:
            assert pred in known, f"{exp.name} needs unknown {pred!r}"


def test_dry_run_lists_every_experiment() -> None:
    args = R.parse_args(["--dry-run"])
    picked = R.select(args)
    order = R.resolve_order(picked)
    assert {e.name for e in order} == {e.name for e in R.MANIFEST}


def test_only_pulls_in_dependencies() -> None:
    """`--only analyze_sweep` must include sweep because analyze_sweep needs it."""
    args = R.parse_args(["--only", "analyze_sweep"])
    picked = R.select(args)
    order = R.resolve_order(picked)
    names = [e.name for e in order]
    assert names == ["sweep", "analyze_sweep"], names


def test_skip_removes_downstream_analyses() -> None:
    """Skipping `sweep` must also drop analyze_sweep — no analysis without input."""
    args = R.parse_args(["--skip", "sweep"])
    picked = R.select(args)
    assert "sweep" not in picked
    assert "analyze_sweep" not in picked


def test_fast_drops_slow_and_very_slow_and_their_downstream() -> None:
    args = R.parse_args(["--fast"])
    picked = R.select(args)
    for n in picked:
        assert not (R.MANIFEST_BY_NAME[n].tags & {"slow", "very_slow"}), (
            f"--fast should have dropped {n}: tags={R.MANIFEST_BY_NAME[n].tags}"
        )
    # analyze_sweep depends on the very_slow sweep, so it must also be dropped.
    assert "analyze_sweep" not in picked


def test_unknown_only_name_errors() -> None:
    with pytest.raises(SystemExit):
        R.select(R.parse_args(["--only", "does_not_exist"]))


def test_paper_claimed_experiments_are_in_manifest() -> None:
    """Every JSON that `test_paper_claims.py` reads must be reproducible here."""
    paper_claimed = {
        "sample_complexity.json",
        "confusability.json",
        "multi_exploit.json",
        "diversity.json",
        "optimal_stopping.json",
        "blast_radius.json",
        "iot_botnet.json",
    }
    declared = set(R.declared_outputs())
    missing = paper_claimed - declared
    assert not missing, (
        f"paper-claimed artifacts not covered by reproduce_all: {missing}"
    )
