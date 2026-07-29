# SERUM — Surviving Contributions (Path A prune)

The purpose of this document is discipline: after the hostile-panel grilling
(`docs/REVIEW_MITIGATION.md`) and the honest re-grading of the 12-point novelty
register (`docs/RESEARCH.md` §"Implementation status & honest verdicts"), which
claims actually *survive*? A paper that leads with all twelve novelties dilutes
its own case and hands reviewers twelve attack surfaces. This is the pruned set:
**four claims we lead with**, each with its single strongest result and its
honest scope, and an explicit triage of every N-item into *lead* or *appendix*.

**The one defensible sentence (revised after Round 4, H1).** *On real network
structure, defending the payload-specific vulnerable subgraph substantially
outperforms structure-only immunization precisely when vulnerable zones diverge
from the topological hubs — a regime real organisational networks exhibit and
hub-dominated backbones do not.* Online exploit inference and the identifiability
characterization are the enabling machinery and honest scope, **not** the headline:
the Round-2/3 grills showed online inference buys little over a good static prior,
so the paper leads with **content-awareness on real topology (C3)**, with C1/C2 as
support and C4 demoted to a robustness note.

**Lead order (post-H1):** C3 (real-data content-aware win) → C2 (the
characterization that explains *when* it works: zone/hub divergence) → C1 (the
online-inference machinery, a refinement) → robustness note (former C4).

---

## The four surviving claims

### C1 — Containment as a POMDP whose hidden state is the exploit, inferred online from the cascade
*(absorbs N2, N3)*

- **Claim.** Formulate payload-unaware containment as a partially observed control
  problem where the latent variable is the attacker's exploit, and infer it online
  from *who falls*: because spread is vulnerability-gated, every propagation-infected
  host is a hard constraint on which CVE is loose.
- **Strongest single result.** The Bayesian belief identifies the true CVE from a
  **median of 5 propagation infections** (1.25% of the fleet) — essentially the
  information-theoretic bit-bound of adaptive group testing
  (hosts/log₂K ≈ 1.02). Artifact: `results/sample_complexity.json`.
- **Honest scope.** Online inference is a *refinement, not the driver* of the
  containment win (see C3 scope, limitation L2): defending the observation-
  *consistent* subgraph already over-covers the true victims. The inference is
  what makes the method *robust* (C4) and what the theory (C2) characterizes.

### C2 — An exact identifiability theorem on observable attributes (the theoretical backbone)
*(absorbs N4)*

- **Claim.** The exploit is identifiable from a saturating outbreak **iff the
  intersection of the infected hosts' vulnerability profiles is a singleton** — a
  set-containment condition on *observable* node attributes that a defender can
  check in advance from its asset inventory. Confusability is exactly the subset
  order on carrier sets. Formally: online, graph-induced, adversarial group testing.
- **Strongest single result (revised, H6).** The genuinely non-trivial content is
  not the singleton condition itself (that is a restatement of the observation
  model, and the "116/116 agreement" is a consistency check on the code, not a
  prediction) — it is the **empirically-measured sample-complexity rate**: on real
  NVD profiles the median is ~1.02·log₂K infections, essentially the i.i.d.
  group-testing bound, whereas a Zipf toy needs ~2.0·log₂K. Real profile
  correlation *bends the rate* toward the information-theoretic optimum. Artifact:
  `results/sample_complexity.json`, `docs/THEORY.md`.
- **Honest scope (H6).** After grilling, C2 is a **characterization + a measured
  rate**, not a headline theorem: the singleton condition is definitional, and the
  separating-system view makes it 1960s combinatorics; the novelty is the *online,
  graph-induced, contagion-realized* instantiation and the real-data rate. Distinct
  from Hoffmann et al. (2020) (latent edge structure) but in an *easier* setting
  (observable attributes), not a strictly stronger theorem.

### C3 — Content-aware containment Pareto-dominates structure-only, on real data
*(absorbs N1, N5, N6, N11, N12)*

- **Claim.** Defending the inferred payload-specific vulnerable subgraph, with an
  adaptive isolate→patch policy, is simultaneously lower-infection and
  higher-availability than every structure-only immunization — because vulnerable
  zones need not coincide with topological hubs.
- **Strongest single result.** On a **real organisational network** (SNAP
  email-Eu-core, 1004 hosts, 42 real departments as software zones, real NVD
  CVEs), structure-only immunization barely helps (17.6% vs 20.1% no-defense)
  while content-aware cuts infection to **11.7% — −28.4% vs the best fixed
  baseline, Wilcoxon p = 1.7×10⁻⁷**, and beats the per-trial ensemble oracle.
  All 11 headline comparisons survive **Holm-Bonferroni** correction (9/11 under
  Bonferroni). Artifacts: `results/real/email_topo.json`, `results/multiplicity.json`.
- **Honest scope.** The favorable regime (zones diverge from hubs) is **not yet
  validated on real host-level enterprise data** (limitation L1) — the join of a
  real segmented topology with real per-host vulnerability inventories is
  proprietary scan data. On synthetic data content-aware does not beat an oracle
  ensemble (p≈0.84); on near-universal exploits, structure-only can win.

### Robustness note (formerly C4 — demoted per Round 4, H5)
*(absorbs N8; the poison-robust agent and the SR5 adaptive adversary)*

> **Why demoted.** "Graceful degradation, never worse than degree under
> poisoning" is a *null result*, not a superiority claim, so it is not a headline
> contribution. It belongs as a robustness note: it shows attacking the inference
> does not make content-awareness *counterproductive*, which is worth stating but
> is not evidence the method wins under attack.

- **Claim.** An attacker cannot defeat the defense by attacking the belief.
  Inference-*evasion* backfires (a confusable payload's victims are a subset of
  its confuser's, so the hedged belief still defends them); belief-*poisoning* is
  absorbed by an audit-and-hedge agent that falls back to structure when its
  belief stops matching the spread.
- **Strongest single result.** Under an **audit-aware best-response poisoner**
  (`serum/attack/adaptive.py`) — the white-box adversary that maximises
  carrier-overlap·leak to keep the trust weight high — the RobustAgent **holds up
  to a poisoning budget of 6% of the fleet** (paired gap over the structural floor
  not significant, p≥0.056). Artifact: `results/adaptive_attack.json`.
- **Honest scope.** The audit is *not* unbreakable: at an extreme 10%-of-fleet
  poisoning the attacker gains a small edge (+0.42pp, uncorrected p=0.022, one
  grid point that fails Holm across the sweep). Breaching it costs a poisoning
  budget twice the defender's containment budget. A *jointly* adaptive adversary
  (payload + timing + placement) remains future work (L5).

---

## Triage of the 12-point novelty register

| # | Novelty | Verdict | Placement |
|---|---|---|---|
| N1 | Vulnerability-gated propagation | Not novel (multitype percolation) — claim no novelty | **Lead** (as model setup, C3), *no novelty claim* |
| N2 | Payload-unaware containment POMDP | Fresh formulation | **Lead** — C1 |
| N3 | Consistency-constrained online exploit inference | Novel cell | **Lead** — C1 |
| N4 | Identifiability theorem on observable profiles | Narrowly novel | **Lead** — C2 |
| N5 | Belief-weighted exposed-vulnerable degree | Modest, defensible | **Lead** (as the C3 mechanism) |
| N6 | Infection–availability Pareto (isolate→patch) | Incremental | **Lead** (as C3 evidence) |
| N7 | Active sensing / VoI honeypot probing | Incremental | **Appendix** |
| N8 | Stackelberg vs the *inference* | Underexplored, defensible | **Lead** — C4 |
| N9 | Learning under exploit-uncertainty (CEM/GNN) | Defensible, not vanilla | **Appendix** (design-validation) |
| N10 | CVSS/LLM threat-intel prior | Open slice, frame modestly | **Appendix** |
| N11 | Real NVD grounding | Validation | **Lead** (the grounding under C3) |
| N12 | Phase diagram of the advantage | Systematization | **Appendix** (supports C3) |

**Extended results → appendix** (each already a `results/*.json` + a paragraph in
`paper/serum.tex` §Extended results, guarded by `tests/test_paper_claims.py`):
confusability K-sweep, polymorphic (multi-exploit) payloads, canary
diversity-for-observability, optimal-stopping honest-negative, cost/blast-radius
value-steering, IoT-botnet (Mirai) application, detection-noise robustness (L4),
multiplicity correction (SR6).

---

## What this means for the paper

- **Lead with C1→C4 in that order** — conceptual core, theory, empirical win,
  robustness. Every headline number in these four is paired, significant, and
  (where a family exists) multiplicity-corrected.
- **Everything else is appendix** — breadth and honest negatives that show the
  framework generalizes and that we grilled ourselves, without competing with the
  four leads for the reviewer's attention.
- **The load-bearing caveat to state up front** (L1): the favorable regime is
  proven on real *vulnerability* data and two real *topologies*, but not yet on a
  real host-level *segmented enterprise inventory* — the single most valuable
  next validation.
