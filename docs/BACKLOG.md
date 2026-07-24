# SERUM — Overnight Autonomous Backlog

The prioritized work queue for autonomous overnight sessions. **Protocol for
every item:** build → `pytest` (keep green) → grill honestly (does it hold? any
overclaim?) → commit + push → append the finding to `docs/DEVLOG.md` → check the
item off here. Record negative results; never overclaim. Work top-down.

## P0 — highest value (do first)

- [x] **Poison-robust defender.** DONE — RobustAgent audits belief vs spread, hedges to structure; tracks the better of belief/structure at every poisoning level. The committee failed to beat belief poisoning
  (correlated failures). Build a defender that (a) *detects* poisoning — e.g. the
  believed exploit's vulnerable subgraph poorly explains the observed infection
  frontier, or belief mass shifts implausibly fast — and (b) *hedges* the budget
  between belief-driven and structure-only targets. Target: never worse than
  structure-only under heavy poisoning, and full content-aware benefit when
  clean. Experiment across decoy counts; commit `scripts/robust.py`.
- [x] **Cost & blast-radius objectives.** DONE — heavy-tailed `value`/`cost_isolate`
  on hosts (`assign_criticality`); `EpisodeResult` now reports `blast_radius`
  and `cost_availability` (backward-compatible defaults). `ContainmentEnv`
  supports `cost_budget=True` (isolation costs `cost_isolate(v)` units). New
  `value_weighted` flag on `ContentAwareAgent` steers the score by neighbour
  value. `scripts/blast_radius.py` (30 paired trials, α=1.2 Pareto,
  value_max=100): **content-aware+value cuts blast_radius by −1.00pp**
  (95% CI [−1.82, −0.19], 18/30 wins) at **+0.83pp** infected_fraction — an
  honest trade, not a Pareto win. Effect vanishes with `value_max=20`
  (a caveat, not a fudge — real fleets are skewed).

## P1 — application & breadth

- [x] **IoT-botnet framing.** DONE — `serum/scenarios/iot.py` (device-type
  firmware monoculture: camera/dvr/router/thermostat/doorbell/light/hub/printer),
  `mirai_payload` targets default telnet creds (spans camera/DVR/router/hub),
  `value` = uplink Mbps so `blast_radius` = DDoS capacity conscripted. Config
  `configs/iot.yaml`, doc `docs/APPLICATION_IOT.md`, experiment
  `scripts/iot_botnet.py` (20 paired trials, n=600, rgg): **content-aware cuts
  DDoS blast −8.71pp vs degree** (CI [−11.13, −6.47], 20/20 wins) while raising
  availability (99.5% vs 91.25%) — Pareto-dominates here. Value-steering adds a
  marginal −2.09pp on blast (CI [−3.98, −0.17], 12/20). Absolute infection is
  high (60%+) because Mirai-style payloads on tight budgets do form botnets —
  the deltas are what to read.
- [x] **Sample complexity of identification.** DONE —
  `identification_trajectory` / `identification_latency` in
  `serum/inference/identifiability.py` (seed profiles excluded from the belief so
  only *propagation* infections count as tests), experiment in
  `scripts/sample_complexity.py`. Real NVD networks (K=30 CVEs, n=400,
  homophily 0.4, 12 nets, 76 identifiable CVEs): **median 5 propagation
  infections** identify the payload = **1.25% of the fleet** (p90 2.25%) =
  18.5% of the reachable component. Empirical hosts / log₂K ≈ 1.02 — matches
  the information-theoretic bit-bound of adaptive group testing. 100% of
  theoretically-identifiable CVEs identify in practice. Caveat: synth K=16 gives
  ratio 2× log₂K, so the "matches the bound" line depends on real profiles
  being more informative than the Zipf toy — not a universal claim.
- [x] **Confusability-graph analysis figure.** DONE — `scripts/confusability.py`
  (8 NVD-derived nets, n=400, K=30, 240 live CVEs). Operational identifiable
  fraction **50.8%**, global (subset-order) **63.7%**; median confuser count 0,
  p90 = 3. K-sweep {10, 20, 30, 50, 80} shows identifiable fraction decays
  67.5% → 20.0% (operational). Figure has three panels: confuser-count
  histogram, identifiable-fraction-vs-K, and a drawn subset-order subgraph.
  Op ≤ global identifiability is cross-checked as a theorem in the tests
  (`test_confusability_distribution_helper_and_ordering`).

## P2 — depth & theory

- [x] **Multi-exploit / polymorphic payloads.** DONE — `MultiPayload` (OR-of-
  exploits) plugs into `ContainmentEnv` unchanged; `serum/inference/multi_exploit.py`
  has hitting-set identifiability + `MultiExploitBelief` (hard belief over size-k
  subsets). Experiment `scripts/multi_exploit.py` on real NVD n=300, K=16:
  identifiable fraction decays **77.8% → 49.6% → 38.2% → 27.1%** for k=1→4;
  k=2 identifiable sets need **median 18 propagation infections** to pin
  (vs 5 for single-CVE), ratio to log₂C(16,2)=6.9 bit-bound is **2.61** (real
  profiles less informative than i.i.d. bits, correlation penalty compounds
  with k). Caveats: brute-force capped at K=16; belief conditions on knowing
  k; no end-to-end containment yet — this closes the *identifiability layer*
  for polymorphic worms, not the defense layer.
- [x] **Optimal-stopping (inference races spread).** DONE — honest negative.
  `serum/agents/stopping.py` (`FixedStopAgent`, `AdaptiveStopAgent`) with two act
  modes (hedge / MAP-commit); experiment `scripts/optimal_stopping.py` on 24
  paired real-NVD trials sweeps T ∈ {0,1,2,3,5,8,12} vs three support-threshold
  adaptive rules. **Wait-vs-spread curve is monotonically increasing** — mean
  infected goes 0.020 → 0.155 (hedge, 7.7×) and 0.021 → 0.153 (commit) as T
  grows; per-trial oracle-best T is **T=0 in 24/24 (hedge)** and 22/24 (commit,
  the 2 exceptions win by ≤1pp at T=1). Every adaptive rule has strictly
  positive gap vs the oracle (all CI95 lower bounds > 0). Takeaway: with a
  perishable per-step budget and a hedged/inferring defender, optimal stopping
  collapses to "act immediately" — a stopping rule adds nothing. Would matter
  only under cumulative budgets or a pathological prior.
- [x] **Diversity-for-observability.** DONE — `serum/inference/diversity.py`
  (`add_canary` / `greedy_canary_plan` / `identifiability_curve`); canaries are
  monotone (adding a host only grows `carriers(c)`, so subset-order dominances
  can only *break*, never appear). Experiment `scripts/diversity.py` on 8 real
  NVD nets, K=30, n=400: baseline 50.8% global / 42.9% operational identifiable;
  greedy hits 100% at **median B*=15 canaries global** (= K_live − I0_global,
  the singleton upper bound) and B*=17.5 operational. Random singletons wander
  to ~85% global / 60% operational at B=30 and typically need ≥2K canaries to
  converge (coupon-collector). Greedy wins 8/8 at every B > 0, Δ CI95 > 0
  throughout. Caveats: singleton greedy is not provably min-canary optimal
  (multi-CVE canaries can pin two CVEs when their dominators are disjoint —
  set-cover follow-up); result is the info-theoretic ceiling, not an ops
  budget with per-host installation constraints.

## P3 — polish & reproduction

- [x] **Expand the paper** (`paper/serum.tex`) with each new result as it lands;
  keep tables/figures in sync. Add group-testing framing to the intro. DONE —
  intro gains a "Formal framing: online, graph-induced group testing" paragraph
  (Rényi/Kautz–Singleton/Atia–Saligrama/Aldridge–Johnson–Scarlett, `log₂K`
  bit-bound); new `\section{Extended results}` covers sample complexity,
  confusability K-sweep, polymorphic payloads, canary diversity, optimal-
  stopping negative, RobustAgent, cost/blast-radius, and IoT-botnet. New
  `tests/test_paper_claims.py` (9 tests) cross-checks every numeric claim
  against `results/*.json` so drift cannot silently ship. 80 tests green.
- [x] **Reproduce-all script** (`scripts/reproduce_all.py`) that regenerates every
  results/ artifact from scratch. DONE — 19-entry declarative manifest covers
  every `results/*.json`/`*.png` on disk (test_no_orphan_result_files guards
  this), with cost tags (fast/medium/slow/very_slow), `--only`, `--skip`,
  `--fast`, `--dry-run`, `--verify` flags, and dependency resolution
  (`analyze_sweep` needs `sweep`). Two-way dependency rule: `--only`
  auto-includes upstream, `--skip`/`--fast` auto-drops downstream. Verified
  subprocess invocation live on `identifiability` (0.5s, rc=0). New
  `tests/test_reproduce_all.py` (11 tests) guards manifest ↔ disk drift.
  Honest scope: this is a plan/orchestration artifact — reproducibility is
  only as bit-perfect as the underlying scripts' seeds, which I did not
  re-verify end-to-end (would take hours).
- [x] **More real topologies** (SNAP Autonomous-Systems graphs) alongside
  email-Eu-core; check the flagship result generalizes. DONE — new
  `scripts/multi_topology.py` runs the identical paired flagship on both
  SNAP topologies (K=30, budget=3, horizon=60, 20 trials each, shared spec).
  **Flagship generalizes on both:** email-Eu-core content-aware **32.33%**
  vs betweenness **34.03%** (Δ=+1.70pp, CI95 [+1.46, +1.94], Wilcoxon
  **p=8.8e-5**, **20/20 wins**); as-internet content-aware **0.07%** vs
  greedy-blocking **1.43%** (Δ=+1.36pp, CI95 [+0.03, +2.98], **p=7.7e-3**,
  9/20 wins — 11 ties, both policies at 0 infected). Absolute deltas are
  smaller on AS because sparse graphs let any defense contain a worm
  fast; the *relative* reduction is 95%+. Artifact
  `results/real/snap_topologies.json`, guarded by
  `tests/test_multi_topology.py` (3 tests) + added to `reproduce_all` manifest.
  Honest caveat: two topologies checked (email + AS), not a sweep across
  every SNAP graph; the AS "one node = one AS" abstraction stretches the
  software-monoculture model but the paired result still passes.

## Done (moved from queue — newest first)

- [x] Committee agent + honest negative result (poisoning not solved by voting).
- [x] Deception / belief-poisoning attacker (soft resists light, not heavy).
- [x] Imperfect inventory = noisy group testing (crossover ~30% miss).
- [x] Group-testing framing of the identifiability theory (missed field found).
- [x] Spread-anonymity: honest one-sided bound (Prop 4), overclaim corrected.
- [x] Comprehensive verified literature review + 40-entry bibliography.
- [x] Paper draft; Pareto front; N7 sensing; N8 evasion; N9 learned; N10 prior.
- [x] Identifiability theorem (100% validated); real-topology flagship result.

## Round 2 — loophole mitigations (from the hostile panel review, docs/REVIEW_MITIGATION.md)

- [x] **SR2 zone-hub divergence metric.** DONE — `serum/inference/divergence.py`
  defines `rank_divergence(g, c) = 1 - Spearman(deg_G(v), vuln_deg(v)) over
  v ∈ carriers(c)` and `hub_swap(g, c, k)` (top-k Jaccard). Experiment
  `scripts/divergence.py` (N=90 real-NVD trials across homophily 0.0–1.0):
  **rank_divergence predicts the per-trial content-aware advantage over
  DegreeDefense (Spearman r=−0.263, permutation p=0.010)** and beats the
  synthetic homophily knob itself (r=−0.027, p=0.81) — the metric captures
  per-trial structural variation the knob cannot. Honest: sign is opposite the
  naive intuition (LOW divergence → LARGER delta, because low divergence means
  well-connected carrier subgraph → bigger outbreaks → more room for CA to
  distinguish itself); locked in a directional test. r²≈0.07 = modest effect.
- [x] **SR6 multiplicity correction.** DONE — `serum/inference/multiplicity.py`
  implements Holm-Bonferroni step-down + plain Bonferroni; `scripts/multiplicity.py`
  curates 11 headline paired-Wilcoxon p-values from JSON artifacts (synth-flagship
  ×2, SNAP email-Eu-core ×2, SNAP AS ×2, BA/WS/RGG synth topologies, adversarial
  evasive + identifiable), deduplicated by seeds/spec. At α=0.05: **Holm rejects
  11/11**; Bonferroni rejects 9/11 (SNAP-AS marginal drops). Largest surviving
  Holm-adj p = 0.042; 5/11 at p_adj < 10⁻³. New Multiplicity paragraph in
  §Extended results, L6 downgraded from "open ack" to "addressed". Guarded by
  `tests/test_multiplicity.py` (12 tests). Honest scope: this corrects
  multiplicity *within* the pre-registered headline set, not researcher
  degrees-of-freedom in which comparisons to headline (a broader problem no
  correction fixes).
- [x] **L4 infection-detection noise.** DONE — two-channel detection-noise model
  (`detection_miss` / `detection_false`) on `ContainmentEnv`; `frontier()` and
  the belief read the corrupted observed set. `scripts/detection_noise.py` (20
  paired trials × 10-point grid, real NVD): content-aware keeps a positive gap
  over degree at 9/10 noise points; the pure 2% false-alarm point ties
  (−0.09pp). Graceful degradation, not a significant win under noise; false
  alarms (which poison the belief) are the sensitive channel. L4 downgraded to
  "addressed".
- [x] **SR5 adaptive adversary.** DONE — `serum/attack/adaptive.py` best-responds
  to the RobustAgent trust audit (maximise carrier-overlap·leak so α stays high
  while true victims leak). `scripts/adaptive_attack.py` (60 paired trials/point,
  real NVD, n=500, K=40): the attack has teeth (drives single soft belief to
  2.5–4.5%) but **RobustAgent holds up to 30 decoys = 6% of fleet** (gap vs
  structural floor not significant, p≥0.056); marginal breach only at 50 decoys
  = 10% of fleet (+0.42pp, uncorrected p=0.022, fails Holm across the grid).
  Bounds L5: audit not unbreakable, but breaching costs 2× the containment
  budget. L5 downgraded to "addressed, bounded caveat". Joint payload+timing
  best-response still open.
- [ ] **Path A prune.** Produce `docs/CONTRIBUTIONS.md`: the 4 claims that
  survive grilling, each with its single strongest result and its honest scope;
  mark which of the 12 novelties move to appendix.
