"""Tests for the Holm-Bonferroni family-wise correction (SR6)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from serum.inference.multiplicity import bonferroni, holm_bonferroni


ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"


def test_holm_matches_worked_example():
    """Textbook Holm-Bonferroni step-down on a small worked example.

    Sorted p:  0.005, 0.011, 0.02, 0.04     (m=4)
    Adj:       0.020, 0.033, 0.04, 0.04     (running max, capped at 1)
    """
    rows = holm_bonferroni([0.02, 0.005, 0.04, 0.011])
    by_label = {r.label: r for r in rows}
    assert abs(by_label["t1"].p_adj - 0.020) < 1e-9   # smallest raw
    assert abs(by_label["t3"].p_adj - 0.033) < 1e-9
    assert abs(by_label["t0"].p_adj - 0.040) < 1e-9   # tied at running max
    assert abs(by_label["t2"].p_adj - 0.040) < 1e-9
    # Original input order preserved
    assert [r.label for r in rows] == ["t0", "t1", "t2", "t3"]


def test_holm_monotone_in_ascending_rank():
    """The running-max ensures adjusted p never decreases as raw p grows."""
    raw = [1e-6, 2e-4, 3e-4, 1e-3, 4e-3, 2e-2, 4e-2, 0.11]
    rows = holm_bonferroni(raw)
    adjs_in_sorted_order = sorted((r.p_adj, r.p_raw) for r in rows)
    for a, b in zip(adjs_in_sorted_order, adjs_in_sorted_order[1:]):
        assert a[0] <= b[0] + 1e-12, "Holm p_adj must be non-decreasing in raw p"


def test_holm_clips_at_one():
    """Adjusted p is capped at 1 even when m*p > 1."""
    rows = holm_bonferroni([0.4, 0.6, 0.9])
    for r in rows:
        assert 0 <= r.p_adj <= 1


def test_bonferroni_uniform_multiplier():
    rows = bonferroni([0.01, 0.02, 0.03])
    assert abs(rows[0].p_adj - 0.03) < 1e-12
    assert abs(rows[1].p_adj - 0.06) < 1e-12
    assert abs(rows[2].p_adj - 0.09) < 1e-12


def test_holm_at_least_as_powerful_as_bonferroni():
    """For every raw p, Holm-adjusted <= Bonferroni-adjusted."""
    raw = [1e-5, 8e-5, 1e-4, 3e-4, 8e-4, 2e-3, 4e-3, 8e-3, 4e-2]
    for h, b in zip(holm_bonferroni(raw), bonferroni(raw)):
        assert h.p_adj <= b.p_adj + 1e-12


def test_holm_reject_flag_matches_alpha():
    """The rejected flag is (p_adj <= alpha), inclusive."""
    rows = holm_bonferroni([0.01, 0.03, 0.06], alpha=0.05)
    # p_adj: sorted 0.01, 0.03, 0.06 -> (3, 2, 1) * (0.01, 0.03, 0.06) with
    # running max = 0.03, 0.06, 0.06.
    by_label = {r.label: r for r in rows}
    assert by_label["t0"].rejected     # 0.03 <= 0.05
    assert not by_label["t1"].rejected  # 0.06 > 0.05
    assert not by_label["t2"].rejected


def test_holm_rejects_none_on_empty():
    assert holm_bonferroni([]) == []
    assert bonferroni([]) == []


def test_holm_rejects_invalid_p():
    with pytest.raises(ValueError):
        holm_bonferroni([-0.1, 0.5])
    with pytest.raises(ValueError):
        holm_bonferroni([0.5, 1.5])


def test_multiplicity_artifact_exists_and_is_consistent():
    """If results/multiplicity.json is on disk, its Holm columns must match
    a fresh recomputation from the raw p-values."""
    path = RESULTS / "multiplicity.json"
    if not path.exists():
        pytest.skip("results/multiplicity.json not present; run "
                    "scripts/multiplicity.py first")
    data = json.loads(path.read_text())
    family = data["family"]
    raw = [row["p_raw"] for row in family]
    labels = [row["label"] for row in family]
    fresh = holm_bonferroni(raw, labels=labels, alpha=data["alpha"])
    for row, r in zip(family, fresh):
        assert abs(row["p_holm_adj"] - r.p_adj) < 1e-12, \
            f"Holm-adj drift for {row['label']}"
        assert row["rejected_holm"] == r.rejected


def test_multiplicity_family_has_the_expected_headlines():
    """The curated family must contain the paper's headline paired
    comparisons (or a superset thereof), keyed by an unambiguous label
    substring, so an accidental deletion is caught."""
    path = RESULTS / "multiplicity.json"
    if not path.exists():
        pytest.skip("results/multiplicity.json not present")
    data = json.loads(path.read_text())
    labels = " || ".join(row["label"] for row in data["family"])
    for anchor in (
        "synth-flagship: content-aware vs best-fixed",
        "synth-flagship: content-aware vs ensemble oracle",
        "SNAP email-Eu-core: content-aware vs best-fixed",
        "SNAP autonomous-systems",
        "synth BA topology",
        "synth WS topology",
        "synth RGG topology",
        "adversarial (evasive)",
        "adversarial (identifiable)",
    ):
        assert anchor in labels, f"missing headline comparison: {anchor!r}"


def test_all_paper_headline_p_values_survive_holm():
    """The headline p-values already cited in the paper (raw p <= 0.01)
    must all survive Holm at alpha=0.05. If a raw p only ever appears at
    0.01--0.05 the paper flags it as marginal explicitly; here we guard
    against a regression where a *headline* claim fails FWER."""
    path = RESULTS / "multiplicity.json"
    if not path.exists():
        pytest.skip("results/multiplicity.json not present")
    data = json.loads(path.read_text())
    for row in data["family"]:
        if row["p_raw"] <= 0.01:
            assert row["rejected_holm"], (
                f"{row['label']} has raw p={row['p_raw']:.4f} but does not "
                f"survive Holm (adj={row['p_holm_adj']:.4f})"
            )


def test_paper_reports_holm_corrected_family():
    """Paper must acknowledge the multiplicity correction and cite the
    family size + reject-rate that matches results/multiplicity.json."""
    path = RESULTS / "multiplicity.json"
    if not path.exists():
        pytest.skip("results/multiplicity.json not present")
    data = json.loads(path.read_text())
    tex = (ROOT / "paper" / "serum.tex").read_text()
    assert "Holm" in tex, "paper must mention the Holm-Bonferroni correction"
    m = data["m"]
    rej = data["summary"]["holm_rejected"]
    # e.g. "11/11" or "$11/11$"
    marker = f"{rej}/{m}"
    assert marker in tex, (
        f"paper should cite the Holm reject rate {marker}"
    )
