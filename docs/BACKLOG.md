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
- [ ] **Confusability-graph analysis figure.** From `confusability_graph`: on
  real data, the distribution of confuser counts, the identifiable fraction, and
  a small drawn example. `scripts/confusability.py`.

## P2 — depth & theory

- [ ] **Multi-exploit / polymorphic payloads.** Hidden state = an exploit *set*;
  belief over sets; identifiability becomes a combinatorial (group-testing with
  multiple defectives) condition. Extend sim + belief + one experiment.
- [ ] **Optimal-stopping (inference races spread).** When should the defender
  commit to acting vs keep watching to identify better? A stopping rule + a
  comparison against fixed-time acting.
- [ ] **Diversity-for-observability.** Given a budget of software reassignments,
  *maximize the identifiable fraction* (design a separating family). Show a
  defender can engineer the fleet so outbreaks self-reveal. Optimization + result.

## P3 — polish & reproduction

- [ ] **Expand the paper** (`paper/serum.tex`) with each new result as it lands;
  keep tables/figures in sync. Add group-testing framing to the intro.
- [ ] **Reproduce-all script** (`scripts/reproduce_all.py`) that regenerates every
  results/ artifact from scratch.
- [ ] **More real topologies** (SNAP Autonomous-Systems graphs) alongside
  email-Eu-core; check the flagship result generalizes.

## Done (moved from queue — newest first)

- [x] Committee agent + honest negative result (poisoning not solved by voting).
- [x] Deception / belief-poisoning attacker (soft resists light, not heavy).
- [x] Imperfect inventory = noisy group testing (crossover ~30% miss).
- [x] Group-testing framing of the identifiability theory (missed field found).
- [x] Spread-anonymity: honest one-sided bound (Prop 4), overclaim corrected.
- [x] Comprehensive verified literature review + 40-entry bibliography.
- [x] Paper draft; Pareto front; N7 sensing; N8 evasion; N9 learned; N10 prior.
- [x] Identifiability theorem (100% validated); real-topology flagship result.
