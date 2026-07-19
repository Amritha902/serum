# SERUM — Overnight Autonomous Backlog

The prioritized work queue for autonomous overnight sessions. **Protocol for
every item:** build → `pytest` (keep green) → grill honestly (does it hold? any
overclaim?) → commit + push → append the finding to `docs/DEVLOG.md` → check the
item off here. Record negative results; never overclaim. Work top-down.

## P0 — highest value (do first)

- [ ] **Poison-robust defender.** The committee failed to beat belief poisoning
  (correlated failures). Build a defender that (a) *detects* poisoning — e.g. the
  believed exploit's vulnerable subgraph poorly explains the observed infection
  frontier, or belief mass shifts implausibly fast — and (b) *hedges* the budget
  between belief-driven and structure-only targets. Target: never worse than
  structure-only under heavy poisoning, and full content-aware benefit when
  clean. Experiment across decoy counts; commit `scripts/robust.py`.
- [ ] **Cost & blast-radius objectives.** Give hosts a `criticality`/`value`
  weight. Add metrics: value-weighted infection (**blast radius**) and
  cost-weighted availability (isolating a critical host costs more). Make the
  budget a *cost* budget. Show content-aware can be steered to protect
  high-value hosts. `scripts/blast_radius.py`.

## P1 — application & breadth

- [ ] **IoT-botnet framing.** A scenario module: device-type firmware zones
  (natural monoculture), a Mirai-style payload, blast radius = DDoS capacity ∝
  infected devices. A config + a short `docs/APPLICATION_IOT.md` + one headline
  experiment. Keep the framework general; IoT is the flagship application.
- [ ] **Sample complexity of identification.** How much of the outbreak must the
  defender observe before the exploit is identified? Curve of support-size /
  identification-latency vs infected fraction, on real data. Ties to group-
  testing rate results (Aldridge–Johnson–Scarlett).
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
