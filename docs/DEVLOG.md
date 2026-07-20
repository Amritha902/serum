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

## Phase 5 — Poison-robust defender (redeems the committee failure)

- **RobustAgent** audits its belief against the spread it predicts: each step it
  measures the fraction of new (propagation) infections that carry the current
  MAP CVE and moves a trust weight `α` toward it, scoring hosts as
  `α·content + (1−α)·structural`. Poisoning is one-shot; the real worm keeps
  revealing the truth, so `α` falls under attack and the agent hedges to
  structure. **Result (scripts/robust.py):** it tracks the *better* of
  {content-aware, degree} at every poisoning level — 1.13% clean (vs degree
  1.71%), 1.49% at 15 decoys (beats both), 1.77% at 30 decoys (vs single-soft's
  collapse to 4.94%). The committee failure is redeemed by *detection + hedging*,
  not ensembling — the honest lesson made concrete.

## Phase 6 — Deep technical grill: what actually drives the win (honest reframe)

A decomposition (content-aware with prevalence vs uniform prior, plus belief
diagnostics) revealed that **the containment advantage does NOT come from
identifying the exploit**:
- the belief ends with ~11 of 40 CVEs still consistent (it does not narrow to 1);
- the MAP is the true CVE only ~25% of the time (usually mis-identifies);
- yet infection is 0.95%, near the oracle's 0.85%, and a *uniform* prior gives
  0.97% (the prior barely matters).

**Honest mechanism.** The win comes from defending the belief-*consistent*
vulnerable subgraph, which works *even under-identification* because the
surviving CVEs are confusers that **share the same victims** (Prop 3) — the same
reason evasion backfires. Containment succeeds because good defense contains the
outbreak in ~3 steps, leaving little evidence, but that little evidence rules out
enough CVEs that the *consistent set's* vulnerable hosts already overlap the true
victims. So the empirical claim is NOT "we identify the exploit"; it is **"we
defend the vulnerable subgraph the observations are consistent with, without
needing to identify the exploit."** The identifiability theorem (Thm 1)
characterises *when* full identification is possible, but containment does not
require it — a cleaner, more robust, and more honest thesis than the original
framing. Paper claims adjusted accordingly.

## Phase 7 — SR3 grill: does online inference earn its keep? (honest: barely)

Tried to mitigate the existential review point (SR3: "containment needs no
identification, so the inference machinery is unnecessary") by finding a regime
where online inference dominates a frozen prior. Added `update_belief=False`
(freeze belief at prior) as an ablation and swept regimes. **Result: online
inference buys only +0.1–0.2 pts everywhere** — including the tight-budget,
low-prevalence regime where it was predicted to matter most (there it was
+0.00 to +0.12 pt). Reason: Prop 3's over-coverage — the true victims are a
*subset* of any consistent confuser's victims, so the belief-weighted defense
covers them with or without identification; inference only trims wasted budget at
the margin. **Honest conclusion (the fix is a reframe, not a regime):** the core
contribution is *content-awareness + over-coverage robustness* (defend the
vulnerable subgraph consistent with observations), NOT online exploit inference,
which is a marginal refinement. The identifiability theorem stands as
*theoretical* characterisation + the group-testing connection, decoupled from the
empirical containment claim. This is uncomfortable but true; the paper's headline
must move off "we infer the exploit."

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

## Phase 8 — Cost & blast-radius objectives

Real fleets are lopsided: a handful of hosts (crown-jewel DBs, DCs, payment
gateways) matter far more than the rest. Fraction infected is not the right
objective in that regime. Added heavy-tailed host `value` + isolation `cost`
(`sim.network.assign_criticality`, Pareto tail), two new metrics on
`EpisodeResult` (`blast_radius` = fraction of total value ever infected;
`cost_availability` = 1 − fraction of total isolation cost spent), and an
optional cost-budget mode on `ContainmentEnv` (`cost_budget=True`, isolation of
host v consumes `cost_isolate(v)` units). Defaults preserve backward
compatibility — with no criticality attached, `blast_radius == infected_fraction`
and `cost_availability == availability` (both properties tested).

Steering: added a `value_weighted` flag to `ContentAwareAgent` — each
susceptible neighbour contributes its `value` to the exposed-vulnerable-degree
score, so budget preferentially cuts off branches whose blast radius would be
largest. Experiment (`scripts/blast_radius.py`, 30 paired trials on real-CVE
networks, α=1.2 Pareto criticality, value_max=100, budget=2):

| policy | inf% | blast% | avail% | cost_av% |
|---|---|---|---|---|
| no-defense | 21.27 | 19.77 | 100 | 100 |
| degree | 18.08 | 16.60 | 94.93 | 95.33 |
| content-aware | 10.49 | 9.33 | 98.35 | 98.63 |
| **content-aware+value** | **11.32** | **8.33** | **98.39** | **98.93** |

**Paired steering effect** (`content-aware+value` − `content-aware`):
- `blast_radius`: **−1.00pp** (95% CI [−1.82, −0.19], 18/30 wins) — significant.
- `infected_fraction`: **+0.83pp** (95% CI [+0.33, +1.35], 5/30 wins).

The trade is real, not free: you buy a ~1pp reduction on the value-weighted
objective by paying ~0.8pp on the plain outbreak count. The point of the item
is that this trade is now *available* — the defender can steer under a
different objective and the framework supports it end-to-end.

**Grilled honestly.** (1) Effect requires meaningfully skewed criticality: with
`value_max=20` the CI straddles 0 (checked). Real fleets ARE skewed, so this is
a fair regime, not a fudge. (2) It is a trade-off, not a Pareto improvement —
protecting value costs a little on raw infection count. (3) The mechanism is
myopic (weights next-hop neighbour values only), so improvements come from
protecting hosts that would infect a high-value host in the *next* step, not
from global reasoning about downstream chains. A tree-lookahead or influence-
maximisation variant could plausibly do better; not attempted this iteration.
(4) `cost_budget=True` is implemented and tested but the headline experiment
runs with `cost_budget=False`, to isolate the effect of the value-weighted
score from the effect of a cost-metered budget. Both together is an open
combination.

## Phase 9 — IoT-botnet application (Mirai-style)

Wired SERUM to its flagship application: Mirai-era IoT DDoS containment.
`serum/scenarios/iot.py` builds a synthetic fleet from a compact device
catalog (`camera / dvr / router / thermostat / doorbell / light / hub /
printer`), each type carrying its own firmware CVE set — product-level
monoculture, in contrast with the enterprise scenario's segment-level
monoculture. `mirai_payload` targets default telnet credentials (cve=0),
which spans camera / DVR / router / hub. `value` on each device = uplink
Mbps, so SERUM's `blast_radius` metric reads directly as DDoS capacity
conscripted (routers 250 Mbps ≫ bulbs 5 Mbps, so the ceiling is dominated
by a small tail — the whole reason the metric matters).

Config: `configs/iot.yaml`. Doc: `docs/APPLICATION_IOT.md`. Headline
experiment: `scripts/iot_botnet.py` (20 paired trials, n=600 on an `rgg`
mesh, budget=3, horizon=25, target=default telnet creds):

| policy | inf% | blast% | avail% |
|---|---|---|---|
| no-defense | 70.97 | 93.77 | 100.00 |
| degree | 67.31 | 89.26 | 91.25 |
| **content-aware** | **60.03** | **80.54** | **99.50** |
| content-aware+value | 59.27 | 78.45 | 99.50 |

**Paired effects.**
- `content-aware` − `degree` on `blast_radius`: **−8.71pp**
  (95% CI [−11.13, −6.47], **20/20 wins**) — decisive.
- `content-aware+value` − `content-aware` on `blast_radius`: −2.09pp
  (95% CI [−3.98, −0.17], 12/20 wins) — the CI just excludes 0, so a real
  but marginal steering effect.
- `content-aware+value` − `content-aware` on `infected_fraction`: −0.76pp
  (CI [−2.11, +0.51], 12/20). Here value-steering does not cost on plain
  outbreak count — different from the enterprise blast-radius run.

**Grilled honestly.**
1. **Absolute numbers are high** (60–90% conscripted). Budget=3 per step on a
   n=600 fleet with a `beta=0.45` (default-telnet-creds is easy) is a *very*
   tight regime — content-aware buys 9pp on DDoS capacity but the botnet
   still forms. This mirrors reality: Mirai conscripted 300k+ devices. Every
   policy is asked to contain a virulent, wide-spread payload with scarce
   response bandwidth; the deltas are what to read, not the levels.
2. **Content-aware is Pareto-better than degree** here (higher availability,
   lower blast, lower infected) — a stronger claim than the enterprise
   blast-radius study, because content-aware mostly *patches* once the belief
   narrows (99.5% avail) while degree keeps isolating (91.25% avail). This is
   an artifact of the payload being very telnet-focused → belief narrows
   fast → the `patch_when_support_leq` switch fires early.
3. **Value-steering is smaller than in enterprise** (−2pp vs −1pp in
   enterprise, but the CI here is nearly at 0). The reason is the same
   mechanism, weaker at this budget: value-weighting redirects marginal
   frontier picks toward router/hub neighbours, but the budget is so tight
   most rounds are forced picks anyway.
4. **No claim of a real-world calibration.** The device catalog is
   illustrative Mirai-era archetypes, not a scanned inventory. The point of
   the item is the *binding*: SERUM plugs into an IoT DDoS setting with no
   simulator changes, and the metrics come out interpretable
   (`blast_radius` = DDoS capacity share). Absolute deltas would move with
   any recalibration, but the headline shape (content-awareness > topology
   for value-weighted objectives) is baked into the model, not the numbers.

## Phase 10 — Sample complexity of identification (group-testing rate on real data)

**What.** How many infected hosts does the defender have to *see* before the
posterior support collapses to a single CVE? New `identification_trajectory`
(step-by-step: infected count → support size) and `identification_latency` in
`serum/inference/identifiability.py`; experiment in `scripts/sample_complexity.py`.
Critical design choice: `known_seeds=True` in the belief so the seeds' own
vulnerability profiles do NOT count as evidence — only *propagation* infections
do. (An earlier iteration with `known_seeds=False` produced a fake-looking
"median=3 hosts" result that just recovered the seed count; caught in the grill.)

**Real-data numbers.** 12 networks × 30 CVEs (400 hosts each, homophily 0.4,
NVD-derived profiles), 76 identifiable-CVE trials:
- **Median 5 propagation infections** to pin the payload's identity.
- **1.25% of the fleet** (0.7–2.0% inter-network range) ever infected at
  identification; p90 = 2.25%.
- **18.5% of the reachable vulnerable component** observed at identification.
- **empirical hosts / log₂K ≈ 1.02** with K=30 → the empirical median lands
  essentially on the information-theoretic bit-bound.
- **Identification rate = 100%** among theoretically-identifiable CVEs — the
  supp(R) prediction survives dropping seed profiles from the belief.

**Group-testing tie-in.** Adaptive noiseless group testing with 1 defective in K
items needs ≥⌈log₂K⌉ tests (Aldridge–Johnson–Scarlett survey, 2019). Each new
propagation infection acts as one such test: it intersects the running support
with that host's carrier set. Real profiles are correlated (segment
monoculture), which could have hurt the rate; empirically it doesn't — the
information-theoretic scaling lands within a small constant of the i.i.d. bound.

**Grill / caveats.**
- On K=16 synth (Zipf profiles, no product structure) the ratio is 2.0× log₂K,
  not 1.0× — the "matches log₂K" line depends on the specific profile
  structure. Real product-based profiles are *more* informative than the Zipf
  toy, not less.
- We only probe CVEs with reachable component ≥10 (otherwise there is nothing
  to observe). Small-component CVEs are dropped honestly, not miscounted.
- The result is a rate/order statement, not an equality: log₂K is the
  information-theoretic *bit-count*; hosts-to-identify is a *test-count* in
  the group-testing analogue. Same order, not the same object.
- 100% identification is a *lemma verification*, not a discovery — Thm 1 already
  predicts it. The novel part is the constant (~log₂K, not O(K)).

Artifacts: `results/sample_complexity.json`, `results/sample_complexity.png`.

## Open / next

- Confusability-graph analysis figure (P1).
- Poison-robust defense: attack detection / budget-hedging (motivated by Phase 4).
- Multi-exploit / polymorphic payloads (hidden state = exploit *set*).
- Optimal-stopping: when to commit to acting vs keep watching (inference races spread).
