# SERUM — Surviving Contributions (Path A prune)

The purpose of this document is discipline: after the hostile-panel grilling
(`docs/REVIEW_MITIGATION.md`) and the honest re-grading of the 12-point novelty
register (`docs/RESEARCH.md` §"Implementation status & honest verdicts"), which
claims actually *survive*? A paper that leads with all twelve novelties dilutes
its own case and hands reviewers twelve attack surfaces. This is the pruned set:
**four claims we lead with**, each with its single strongest result and its
honest scope, and an explicit triage of every N-item into *lead* or *appendix*.

**The one defensible sentence.** *Online inference of an unobserved exploit from
the shape of a vulnerability-gated outbreak — with an exact identifiability
condition on observable host attributes — driving budgeted, content-aware
containment, validated on real NVD/CVE data.* That is the cell CyGym (2025)
leaves open (it uses a static prior with no online belief update).

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
- **Strongest single result.** The Bayesian belief recovers the true CVE exactly
  when and only when the theorem predicts it: **116/116 = 100% agreement** on
  real-data networks; ~54% of real CVEs are identifiable. Artifact:
  `scripts/identifiability.py`, `docs/THEORY.md`.
- **Honest scope.** Distinct from cascade-mixture identifiability (Hoffmann et
  al. 2020), whose condition is on *latent* edge structure; ours is on observable
  attributes and holds online per cascade. The theorem *characterizes* when full
  identification is possible — it is not itself the empirical win.

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

### C4 — Robust to adversaries that attack the inference, within stated bounds
*(absorbs N8; adds the poison-robust agent and the SR5 adaptive adversary)*

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
