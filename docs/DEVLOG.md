# SERUM — Development Log

A running record of what was built, what was found, and (crucially) what was
*disproven* under self-grilling. This log is deliberately honest: negative
results and corrected overclaims are recorded, not hidden. Reverse-chronological
within phases; see `git log` for exact commits.

## What SERUM is (one paragraph)

Malware spreads only across hosts running the software it exploits, so the worm's
real contagion graph is the *vulnerable subgraph* for its target CVE. SERUM is a
defender that does **not** observe the payload and must **infer which exploit is
spreading, online, from who gets infected** (a Bayesian belief / POMDP), then
contain it under a budget. Core reframe: *the spread pattern is a measurement
device for the invisible exploit* — malware attribution from contagion topology,
not from signatures. Formally this is **online, graph-induced, adversarial group
testing** (Theme 6 of the literature review).

## Phase 1 — Core system

- Vulnerability-gated SI/SIR simulator; heterogeneous CVE profiles; budgeted
  patch/isolate/segment containment POMDP.
- Bayesian exploit belief (hard consistency + soft noise-robust likelihood).
- Content-aware agent (belief-weighted exposed-vulnerable degree; isolate→patch
  switch). Baselines: random, degree, betweenness, eigenvector, acquaintance,
  greedy-blocking. Oracle + oracle-after-delay bounds.
- Rigorous eval: paired trials, bootstrap CIs, Wilcoxon tests, randomized targets.

## Phase 2 — Real data & realism

- NVD/CVE ingestion → cleaning → CPE/CVSS-grounded host profiles.
- Segment-correlated software (monoculture within connected zones) — makes real
  worms propagate; vulnerable zones diverge from topological hubs.
- **Flagship real-topology result** (SNAP email-Eu-core, 42 real departments):
  content-aware 11.7% vs best structural 17.6% infection, **−28.4%, p=1.7e-7**;
  beats the ensemble oracle. Structure-only barely helps because department-zones
  ≠ hubs — the thesis, on a real network.

## Phase 3 — Theory

- **Identifiability theorem** (Thm 1): exploit identifiable iff the intersection
  of infected hosts' profiles is a singleton. Validated 116/116 = 100% against
  the belief. ~54% of real CVEs identifiable from a saturating outbreak.
- **Group-testing framing** (found via self-grill): Thm 1 is a separating-system
  condition (Rényi 1961); confusers are cover-free-family violations
  (Kautz–Singleton 1964); imperfect inventory = noisy group testing; sensing =
  adaptive group testing. Unifies the whole roadmap.

## Phase 4 — Adversarial & robustness

- **N8 evasion backfires** (proven + measured): an attacker picking a confusable
  payload does *not* erode the content-aware edge (+22.4% vs +17.7%), because
  confusers share victims (Prop 3).
- **Imperfect inventory** (noisy group testing): content-awareness survives
  realistic error (+9.9% at 15% miss) but has a **crossover ~30% miss**; at 50%
  miss it is *worse* than structure-blind defense. Inventory must be >~70%
  complete to pay off.
- **Deception / belief poisoning**: soft belief resists *light* poisoning but is
  overwhelmed by *heavy* poisoning; hard-belief damage saturates. Neither belief
  fully solves it.

## Honest corrections & negative results (the grill working)

1. **Overclaim caught — "spread–anonymity duality".** The clean "a worm can't
   spread AND hide" is FALSE: measured spread↔anonymity correlation is +0.34.
   Corrected to a one-sided bound (Prop 4): *wide* outbreaks are forced toward
   identifiability, but stealthy worms can hide. Anonymity peaks at *moderate*
   prevalence.
2. **Overclaimed early — "52/54, halves infection".** Replaced with paired,
   randomized-target, strong-baseline numbers (significant vs best fixed
   baseline; NOT vs an oracle ensemble on synthetic data). Reported both.
3. **Negative result — committee doesn't beat poisoning.** A committee of diverse
   belief-agents (soft at several noise levels, hard, uniform) with median voting
   does NOT defeat belief poisoning: the belief members fail in a *correlated*
   way and outvote the structural minority. Diverse beliefs ≠ robust beliefs.
   Real fix (future): attack detection or budget-hedging, not ensembling.
4. **Learned policy** matches, does not beat, the hand-designed agent — but
   independently rediscovers the belief features (validates the design), which is
   the honest claim.

## Missed fields found via grilling

- **Group testing / separating systems / superimposed codes** (Dorfman 1943,
  Rényi 1961, Kautz–Singleton 1964, Du–Hwang, Aldridge–Johnson–Scarlett 2019,
  Atia–Saligrama 2012). The rigorous home for the identifiability results and the
  adversarial/noisy extensions.

## Current state

31 tests passing; ~ two dozen commits; pushed to github.com/Amritha902/serum.
Docs: RESEARCH.md (12-novelty register), THEORY.md (theorems), LITERATURE_REVIEW.md
(6 themes, verified), RELATED_WORK.md (audit), this DEVLOG. Paper draft:
paper/serum.tex. Experiment outputs: results/ (JSON + figures).

## Open / next

- Application framing: **IoT botnet** (device-firmware zones, DDoS blast radius).
- Objectives beyond availability: **cost** and **blast radius** (host criticality).
- Poison-robust defense: attack detection / budget-hedging (motivated by Phase 4).
- Multi-exploit / polymorphic payloads (hidden state = exploit *set*).
- Optimal-stopping: when to commit to acting vs keep watching (inference races spread).
