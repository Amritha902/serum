"""Family-wise multiplicity correction for headline paired comparisons (SR6).

Motivation. SERUM reports many paired-Wilcoxon p-values across different
experiments (synthetic-CVE flagship, SNAP topologies, BA/WS/RGG synthetic
topologies, adversarial attackers, IoT-botnet). Reporting each marginal p-value
alone inflates the family-wise error rate. Reviewers will (rightly) ask what
survives a multiplicity correction. The Holm-Bonferroni step-down procedure
controls the FWER at level ``alpha`` under arbitrary dependence between tests
and is uniformly more powerful than plain Bonferroni.

Algorithm (Holm 1979, "A Simple Sequentially Rejective Multiple Test
Procedure"). Sort p-values ascending: p_(1) <= p_(2) <= ... <= p_(m). The
adjusted p-value is p_adj(i) = min(1, max_{k<=i} (m - k + 1) * p_(k)) with the
running maximum enforcing monotonicity. Reject H_(i) iff p_adj(i) <= alpha.

Returns raw indices (matching the input order) so the caller can rebuild a
labelled table without shuffling.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MultiplicityRow:
    """One test in a family, with its raw and Holm-Bonferroni-adjusted p."""

    label: str
    p_raw: float
    p_adj: float
    rank: int
    rejected: bool


def holm_bonferroni(pvals, labels=None, alpha: float = 0.05):
    """Holm-Bonferroni step-down FWER-adjusted p-values.

    Parameters
    ----------
    pvals : sequence of float in [0, 1]
        Raw two-sided p-values for the family of tests.
    labels : sequence of str, optional
        Human-readable label per test; defaults to ``"t{i}"``.
    alpha : float
        Nominal FWER level (used only to compute the ``rejected`` flag).

    Returns
    -------
    list[MultiplicityRow]
        One row per input test, in the *original* input order, each carrying
        ``p_raw``, ``p_adj``, its ascending ``rank`` (1-based), and the
        boolean ``rejected`` at level ``alpha``. Adjusted p-values are
        monotone in the ascending rank (enforced by a running maximum) and
        clipped to ``[0, 1]``.
    """
    m = len(pvals)
    if m == 0:
        return []
    if labels is None:
        labels = [f"t{i}" for i in range(m)]
    if len(labels) != m:
        raise ValueError(f"labels length {len(labels)} != pvals length {m}")
    for p in pvals:
        if not (0.0 <= p <= 1.0):
            raise ValueError(f"p-value {p} out of [0, 1]")

    order = sorted(range(m), key=lambda i: pvals[i])
    running_max = 0.0
    p_adj_sorted = [0.0] * m
    for rank_idx, orig_idx in enumerate(order):
        raw = pvals[orig_idx]
        candidate = (m - rank_idx) * raw
        if candidate > running_max:
            running_max = candidate
        p_adj_sorted[rank_idx] = min(1.0, running_max)

    rows = [None] * m
    for rank_idx, orig_idx in enumerate(order):
        rows[orig_idx] = MultiplicityRow(
            label=labels[orig_idx],
            p_raw=float(pvals[orig_idx]),
            p_adj=float(p_adj_sorted[rank_idx]),
            rank=rank_idx + 1,
            rejected=(p_adj_sorted[rank_idx] <= alpha),
        )
    return rows


def bonferroni(pvals, labels=None, alpha: float = 0.05):
    """Plain Bonferroni for comparison. Adjusted p = min(1, m * p_raw).

    Always more conservative than Holm; included so the table can show both.
    """
    m = len(pvals)
    if m == 0:
        return []
    if labels is None:
        labels = [f"t{i}" for i in range(m)]
    order = sorted(range(m), key=lambda i: pvals[i])
    rank_of = {orig: r for r, orig in enumerate(order)}
    return [
        MultiplicityRow(
            label=labels[i],
            p_raw=float(pvals[i]),
            p_adj=min(1.0, m * float(pvals[i])),
            rank=rank_of[i] + 1,
            rejected=(min(1.0, m * float(pvals[i])) <= alpha),
        )
        for i in range(m)
    ]
