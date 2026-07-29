"""Paper ↔ results sync test.

Every headline number in `paper/serum.tex` must be recomputable from a file in
`results/`. If a JSON artifact drifts (or a paper number is edited without
regenerating the experiment), this test fails loudly so we do not ship
overclaimed or stale numbers.

Only claims that appear in the paper are checked here — the goal is to keep
the two in lockstep, not to re-verify the science (that is what the individual
experiment scripts + `honest-check` do).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PAPER = ROOT / "paper" / "serum.tex"
RESULTS = ROOT / "results"


@pytest.fixture(scope="module")
def tex() -> str:
    return PAPER.read_text()


def _load(name: str) -> dict:
    return json.loads((RESULTS / name).read_text())


def test_sample_complexity_claims(tex: str) -> None:
    d = _load("sample_complexity.json")["overall"]
    assert d["median_hosts_at_id"] == 5.0
    assert abs(d["median_infected_frac_at_id"] - 0.0125) < 1e-9
    assert abs(d["p90_infected_frac_at_id"] - 0.0225) < 1e-9
    assert d["identification_rate"] == 1.0
    ratio = d["empirical_hosts_over_log2K"]
    assert abs(ratio - 1.02) < 0.02
    assert "median of 5 propagation" in tex
    assert "$1.25\\%$" in tex and "p90{=}2.25\\%$" in tex
    assert "$100\\%$" in tex and "\\approx 1.02" in tex


def test_confusability_claims(tex: str) -> None:
    d = _load("confusability.json")
    assert abs(d["identifiable_fraction_op"] - 0.508) < 0.002
    assert abs(d["identifiable_fraction_global"] - 0.6375) < 0.001
    assert d["op_summary"]["median"] == 0.0
    assert d["op_summary"]["p90"] == 3.0
    assert "operational identifiable fraction $50.8\\%$" in tex
    assert "global $63.7\\%$" in tex
    for row in d["K_sweep"]:
        K = row["K"]
        if K in (10, 20, 30, 50, 80):
            live = row["mean_live"]
            assert f"{K} & {live:.1f}" in tex, f"K-sweep row K={K} missing"


def test_multi_exploit_claims(tex: str) -> None:
    d = _load("multi_exploit.json")
    fracs = [row["fraction"] for row in d["size_sweep"]]
    assert [round(f * 1000) / 10 for f in fracs] == [77.8, 49.6, 38.2, 27.1]
    assert d["k2_median_infections"] == 18.0
    assert abs(d["k2_ratio_hosts_over_bits"] - 2.61) < 0.02
    assert "77.8\\%{\\to}49.6\\%{\\to}38.2\\%{\\to}27.1\\%$" in tex
    assert "median of 18 propagation infections" in tex
    assert "ratio of $2.61$" in tex


def test_diversity_claims(tex: str) -> None:
    d = _load("diversity.json")
    assert d["b_star_greedy_global_median"] == 15.0
    assert d["b_star_random_over_greedy_global"] == 4.0
    assert d["n_trials"] == 8
    assert "median $B^\\star=15$" in tex
    assert "$4\\times$ ratio" in tex
    assert "$8/8$ trials" in tex


def test_optimal_stopping_claims(tex: str) -> None:
    d = _load("optimal_stopping.json")["means"]
    fixed_hedge = [d[f"fixed-t{t}.hedge"] for t in (0, 1, 2, 3, 5, 8, 12)]
    assert [round(x, 3) for x in fixed_hedge] == [0.020, 0.033, 0.048, 0.065, 0.090, 0.124, 0.155]
    fixed_commit = [d[f"fixed-t{t}.commit"] for t in (0, 1, 2, 3, 5, 8, 12)]
    assert [round(x, 3) for x in fixed_commit] == [0.021, 0.031, 0.047, 0.062, 0.089, 0.124, 0.153]
    # Monotone increasing in T (both modes) — the honest-negative headline.
    assert all(a <= b + 1e-9 for a, b in zip(fixed_hedge, fixed_hedge[1:]))
    assert all(a <= b + 1e-9 for a, b in zip(fixed_commit, fixed_commit[1:]))
    assert "$T{=}0$ in $24/24$" in tex
    assert "hedge  & 0.020 & 0.033 & 0.048 & 0.065 & 0.090 & 0.124 & 0.155" in tex


def test_blast_radius_claims(tex: str) -> None:
    d = _load("blast_radius.json")
    steer_blast = d["paired_steer_blast"]
    assert abs(steer_blast["mean"] * 100 - (-1.00)) < 0.05
    assert steer_blast["wins"] == 18
    steer_inf = d["paired_steer_infected"]
    assert abs(steer_inf["mean"] * 100 - 0.83) < 0.05
    assert "$-1.00$pp" in tex and "$+0.83$pp" in tex
    assert "$18/30$ wins" in tex


def test_iot_botnet_claims(tex: str) -> None:
    d = _load("iot_botnet.json")
    ca_vs_deg = d["paired_content_aware_vs_degree_blast"]
    assert abs(ca_vs_deg["mean"] * 100 - (-8.71)) < 0.05
    assert ca_vs_deg["wins_a_lower"] == 20
    steer = d["paired_steer_blast"]
    assert abs(steer["mean"] * 100 - (-2.09)) < 0.05
    assert "$-8.71$pp" in tex and "$20/20$ wins" in tex
    assert "$-2.09$pp" in tex and "$12/20$" in tex


def test_closest_baselines_claims(tex: str) -> None:
    # G1 head-to-head vs the closest prior systems (CyGym-static, DAVA-style).
    d = _load("closest_baselines.json")
    dava = d["content_aware_vs_dava"]
    cyg = d["content_aware_vs_cygym_static"]
    assert round(dava["abs_reduction"] * 100, 2) == 0.74
    assert round(dava["rel_reduction"] * 100, 1) == 43.8
    assert dava["wins_of_n"] == "17/40"
    assert round(cyg["abs_reduction"] * 100, 2) == 0.19
    assert round(cyg["rel_reduction"] * 100, 1) == 16.6
    assert cyg["wins_of_n"] == "8/40"
    assert round(d["means_infected"]["dava"] * 100, 2) == 1.70
    assert round(d["means_infected"]["degree"] * 100, 2) == 1.52
    for s in ("$+0.74$pp", "$+43.8\\%$", "$+0.19$pp", "$+16.6\\%$", "$8/40$"):
        assert s in tex, f"closest-baselines claim missing: {s}"


def test_inference_value_claims(tex: str) -> None:
    # G2 when is online inference load-bearing (good vs misleading prior).
    d = _load("inference_value.json")
    assert round(d["good_prior"]["abs_reduction"] * 100, 2) == 0.19
    assert round(d["misleading_prior"]["abs_reduction"] * 100, 2) == 0.44
    assert round(d["misleading_prior"]["p"], 3) == 0.018
    for s in ("$+0.19$pp", "$+0.44$pp", "p=1.8\\times10^{-2}"):
        assert s in tex, f"inference-value claim missing: {s}"


def test_homophily_sensitivity_claims(tex: str) -> None:
    # G6 the advantage survives at homophily 0 (not a manufactured-regime artifact).
    d = _load("homophily_sensitivity.json")
    r0 = [r for r in d["grid"] if r["homophily"] == 0.0][0]
    peak = max(d["grid"], key=lambda r: r["edge_pp"])
    assert round(r0["edge_pp"] * 100, 2) == 0.26
    assert round(r0["p"], 5) == 0.00065
    assert peak["homophily"] == 0.2 and round(peak["edge_pp"] * 100, 2) == 0.60
    for s in ("$+0.26$pp", "p=6.5\\times10^{-4}", "$+0.60$pp"):
        assert s in tex, f"homophily-sensitivity claim missing: {s}"


def test_group_testing_framing_in_intro(tex: str) -> None:
    intro_start = tex.index("\\section{Introduction}")
    formulation_start = tex.index("\\section{Problem formulation}")
    intro = tex[intro_start:formulation_start]
    assert "group testing" in intro.lower(), "Intro must mention group testing framing"
    assert "\\log_2 K" in intro, "Intro should invoke the log_2 K bit-bound"
    assert "R\\'enyi" in intro or "Renyi" in intro
    assert "Kautz--Singleton" in intro or "Kautz" in intro


def test_extended_section_exists(tex: str) -> None:
    # Extended results were moved to a proper appendix (grill G12: enforce the
    # four-claim prune so the main body leads with the core claims).
    assert "\\section{Extended results and honest negatives}" in tex
    assert "\\appendix" in tex
    assert "\\label{sec:extended}" in tex
    for anchor in (
        "Sample complexity of identification",
        "Confusability decays with $K$",
        "Polymorphic (multi-exploit) payloads",
        "Diversity-for-observability",
        "Optimal stopping is trivially T{=}0",
        "Poison-robust defender",
        "Cost \\& blast-radius",
        "IoT-botnet application",
    ):
        assert anchor in tex, f"missing extended paragraph: {anchor}"
