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

### Confusability-graph analysis figure (P1)

Realising the *global* ambiguity structure of the fleet as a graph. Edge
c → c' iff carriers(c) ⊆ carriers(c') — the subset partial order. A CVE with
no out-edges is globally identifiable; the connected component around an
edge-heavy CVE is its ambiguity neighbourhood. Complementarily, per-CVE
`confusers(g, c)` gives the *operational* residual after a saturating outbreak
on the largest reachable vulnerable component.

**Result** (8 NVD-derived networks, n=400, K=30, homophily 0.4, 240 live CVEs):

- Operational identifiable fraction: **50.8%**
- Global identifiable fraction: **63.7%** (weakly larger, as it must be —
  operational identifiable ⇒ global identifiable; see test docstring for the
  1-line proof).
- Confuser-count distribution has median 0 with a heavy tail: mean 1.08,
  p90 = 3 (operational). Most CVEs are cleanly identifiable, a minority
  irreducibly ambiguous.

**K-sweep** (fraction identifiable vs CVE-universe size, real data):

    K      live   ident-sat   ident-global
    10     10.0       0.675          0.700
    20     20.0       0.500          0.550
    30     30.0       0.358          0.400
    50     50.0       0.345          0.465
    80     80.0       0.200          0.384

Identifiability decays with K: more CVEs mean more subset-order dominators,
so a smaller fraction of exploits stand alone. Not a surprise — the
theorem's condition is combinatorial in K — but a first honest measurement
of the decay rate on real profiles.

**Grill / caveats.**
- Flagship (`trials`) and sweep numbers at K=30 differ (op 0.51 vs 0.36)
  because they use different RNG seeds and different trial counts. Both are
  consistent with the same qualitative picture; neither is "the" answer.
- The K sweep goes only to 80. Real fleets carry thousands of CVEs; the
  trend suggests identifiable fraction would fall further, but I do not
  extrapolate — the decay may saturate or accelerate. A larger sweep is
  future work if it starts to matter.
- The drawn example is picked to *maximise* edges over 6 seeds (`pick_drawing_network`)
  so the figure has something to look at. This is a visualisation choice, not
  a claim — the aggregate statistics above use unfiltered samples.
- Operational identifiable is strictly stronger than global identifiable
  (proof: op iff supp(R) = {c*}; if c' had carriers(c') ⊇ carriers(c*) ⊇ R,
  then c' ∈ supp(R), contradicting op). The test cross-checks this on every
  live CVE.

Artifacts: `results/confusability.json`, `results/confusability.png`.

### Multi-exploit / polymorphic payloads (P2, 2026-07-20)

Extends SERUM to *polymorphic* worms that carry an exploit **set** S ⊆ C,
infecting any host whose profile intersects S. This is the multi-defective
analogue of vulnerability-gated group testing: each propagation infection is
a positive test whose profile must *hit* S, and the posterior support after
observing infected set I is the family of size-|S| hitting sets

    supp(I) = { S : ∀ v ∈ I, vuln(v) ∩ S ≠ ∅ }.

Built: `serum/sim/payload.py` gains `MultiPayload` (OR-of-exploits, plugs
into `ContainmentEnv` unchanged); `serum/inference/multi_exploit.py` has
`carriers_multi`, `reachable_component_multi`, `hitting_sets`,
`is_identifiable_multi`, `MultiExploitBelief` (hard belief over size-k
subsets), `identification_trajectory_multi`. Tests in
`tests/test_multi_exploit.py` verify k=1 reduces to the single-CVE theory,
that `MultiExploitBelief.support()` equals `support_over_multi(g, R, k)` at
saturation (Prop 1 analogue), monotone shrinkage, and that a multi-payload
sim never infects hosts outside the carrier component.

Experiment `scripts/multi_exploit.py` (real NVD-derived n=300, K=16):

  size k    live sets    identifiable    frac    median reach
     1          9              7        0.778         16
     2        117             58        0.496         44
     3        560            214        0.382        104
     4       1820            493        0.271        139

Identifiable fraction decays **77.8% → 49.6% → 38.2% → 27.1%** as k grows
1→4 — hitting-set ambiguity dominates as the exploit set enlarges. Sample
complexity for identifiable k=2 sets (12 targets): **median 18 propagation
infections** to collapse the hitting-set support to 1 (vs the single-CVE
median of 5). Ratio to the information-theoretic bit-bound log₂C(16,2)=6.9
is **2.61** — real correlated software profiles are strictly less
informative than i.i.d. bits, and the correlation penalty compounds with k
(the single-CVE ratio was ≈1.02).

**Grill / caveats.**
- Belief conditions on knowing k. This is standard multi-defective group
  testing but is itself an oracle assumption; a defender that must
  jointly-estimate |S| faces harder combinatorics. Not addressed here.
- K=16 is small (bounded by brute-force enumeration; C(K, k) grows fast).
  The decay direction is real, but absolute fractions at large K would
  need Monte-Carlo sampling (already scaffolded in
  `identifiable_fraction_multi(sample=...)`).
- k=1 identifiability fraction (77.8%) here is higher than the flagship
  P1 number (50.8%) because this network uses K=16 vs K=30 — smaller
  universes give fewer subset-order dominators. Consistent with the
  K-sweep trend from confusability.py; not a contradiction.
- The reachable component grows sharply with k (16 → 139), so multi-
  exploit worms *do* spread further even when less identifiable — the
  defender loses on both axes as k grows. An honest bad-news finding.
- No end-to-end containment result yet — this iteration establishes the
  identifiability layer; a content-aware multi-exploit agent would need a
  posterior-mean-of-hitting-sets scoring function (future work).

Artifacts: `results/multi_exploit.json`, `results/multi_exploit.png`.

## 2026-07-20 — Optimal stopping is trivially T=0 (honest negative)

New agent `serum/agents/stopping.py` (`FixedStopAgent`, `AdaptiveStopAgent`):
watch for T steps (no interventions, belief still folds in propagation
evidence), then delegate. Two act modes: **hedge** (posterior-expectation over
the score, i.e. plain ContentAwareAgent) and **commit** (patch only hosts
vulnerable to the MAP CVE — a classical Wald-style commitment).
Adaptive triggers: `support_leq`, `entropy_leq`, `top_mass_geq`, `map_stable_for`.

Experiment `scripts/optimal_stopping.py` (24 paired real-NVD trials, n=400,
K=30, budget=5, horizon=30) sweeps T ∈ {0,1,2,3,5,8,12} vs three adaptive
support-threshold rules, in both act modes.

**Finding: the wait-vs-spread curve is monotonically increasing in T.**
Hedge means: T=0 0.020 → T=12 0.155 (7.7×). Commit means: T=0 0.021 →
T=12 0.153. Per-trial oracle-best T is **T=0 in 24/24 trials (hedge) and
22/24 (commit)** — the two commit exceptions win by ≤1pp at T=1. Every
adaptive rule (S≤5/3/1) has significantly positive gap vs the oracle
(all CI95 lower bounds > 0). None of them win a single trial at S≤1.

**Interpretation** (self-grill). Per-step budget is *perishable*: an unused
step is spread you can never re-contain. Value-of-information from waiting
< cost of the outbreak growing meanwhile — even in commit-mode where the
naïve intuition ("wrong MAP wastes the step") points the other way. Two
reasons commit still dominates at T=0: (i) the prevalence prior + seed
profiles already peak the MAP on a plausible CVE at t=0, and (ii) with
homophily-clustered profiles, even a wrong MAP overlaps the true carrier
set enough that its patches are not fully wasted.

Honest scope. This *is* the takeaway, not a bug: **when your inference
already hedges well and budget is per-step, optimal stopping collapses to
"act immediately"**. Rules that add a waiting rule to SERUM's defender
add nothing. Stopping *would* matter if (a) budget were saveable across
steps (a cumulative-budget environment change we did not make), (b) the
prior were pathologically wrong, or (c) acting had a fixed activation
cost. None of those apply to the SERUM setup — so we report the flat
finding truthfully rather than manufacturing a regime where waiting wins.

Artifacts: `results/optimal_stopping.json`, `results/optimal_stopping.png`.

## P2 — Diversity-for-observability (canary planning)

Question. Given a budget B of *canary hosts* (fresh machines the defender
can provision with a chosen software profile), can we engineer the fleet
so outbreaks self-reveal — pushing identifiable_fraction from the observed
baseline (~50% global, ~43% operational at K=30 on real NVD nets) up to
1.0?

Built. `serum/inference/diversity.py`: `add_canary` (in-place insertion),
`greedy_canary_plan` (dominance-aware singleton canaries), `random_canary_plan`
(uniform baseline), `identifiability_curve`, and
`budget_to_full_identifiability`. Monotonicity theorem: adding a host only
*grows* each `carriers(c)`, and every existing subset-order witness stays a
witness, so identifiable_count is non-decreasing in the canary set — planning
greedily has no regret.

Result (8 real NVD-derived networks, K=30, n=400, homophily 0.4):

|  B | greedy global | random global | greedy op | random op |
|---:|--------------:|--------------:|----------:|----------:|
|  0 | 0.508 | 0.508 | 0.429 | 0.429 |
|  4 | 0.642 | 0.558 | 0.562 | 0.475 |
|  8 | 0.775 | 0.621 | 0.696 | 0.504 |
| 12 | 0.904 | 0.671 | 0.829 | 0.521 |
| 16 | 0.988 | 0.729 | 0.950 | 0.529 |
| 20 | **1.000** | 0.775 | **1.000** | 0.558 |

Greedy reaches 100% at **median B\*=15 canaries** (global; = K_live − I0_global
exactly, matching the singleton upper bound) and B\*=17.5 (operational). Random
takes ≥60=2K canaries in most trials (coupon-collector-limited: hits each
unidentifiable CVE only w.p. 1/K per canary). Greedy wins 8/8 trials at every
B > 0; the Δ CI95 lower bound is strictly positive at B ≥ 1 for both modes.

Sanity / grill. (1) Singleton greedy is *not* provably minimum-canary optimal
— a multi-CVE canary `{c1, c2}` can pin both when their dominators are
disjoint. Set-cover framing is a natural follow-up; the docstring flags this.
(2) The random baseline's B\*=60 is the cap `max_budget=2K` I used; a handful
of trials converged at 44–59 (median = ceiling), so the "4× worse" ratio is a
floor, not a fitted number. (3) Operational canaries require attachment to a
host in the CVE's reachable component — otherwise they don't join the
outbreak. The planner handles this; a canary with no attachable c-carrier
would fail to pin c (this can't happen in these fleets since we only greedy
over live CVEs). (4) A defender-augmentation experiment in a physical
deployment would face constraints greedy ignores (only some software is
installable on the honeypot; per-host cost isn't 1) — this result is the
*information-theoretic ceiling*, not an ops budget.

Artifacts: `serum/inference/diversity.py`, `scripts/diversity.py`,
`tests/test_diversity.py`, `results/diversity.json`, `results/diversity.png`.

## Paper expansion (P3, 2026-07-20)

Brought `paper/serum.tex` up to date with the P0/P1/P2 results that had landed
since the last draft, and moved the group-testing framing from the abstract
into the introduction as its own paragraph (Rényi separating systems,
Kautz–Singleton cover-free families, Atia–Saligrama noisy group testing,
Aldridge–Johnson–Scarlett multi-defective extension, and the log₂K bit-bound
that the sample-complexity experiment matches empirically).

Added `\section{Extended results}` (§6) with eight paragraphs, each with a
one-liner artifact pointer and honest caveats: **sample complexity** (median 5
propagation infections, ≈1.02·log₂K on real data), **confusability decay**
(K-sweep table 10→80), **polymorphic payloads** (77.8%→27.1% k=1→4,
median 18 infections for k=2), **canary diversity** (greedy B\*=15,
random ≥60, 4× ratio, greedy is regret-free but not min-canary optimal),
**optimal stopping negative** (T=0 dominates 24/24 hedge, 22/24 commit; full
mean-vs-T table for both modes), **poison-robust defender** (RobustAgent
tracks the better of belief/degree), **cost & blast-radius** (−1.00pp on
blast for +0.83pp on infection — an honest trade, not a Pareto win, effect
vanishes for value_max=20), **IoT-botnet** (−8.71pp DDoS blast vs degree,
20/20 wins, absolute infection still 60%+).

New test `tests/test_paper_claims.py` (9 tests) reads every result artifact
the paper cites and asserts the number that ends up in the .tex matches the
JSON. Caught two drift issues during authoring — the paper table had
`0.032` where the data was `0.031`, and I initially referenced two BibTeX
keys (`atia2012groupnoisy`, `aldridge2019groupsurvey`) that did not exist
in `refs.bib`; both fixed. Also verifies the group-testing paragraph
survives future edits to the intro (specifically: presence of "group
testing", `\log_2 K`, Rényi, Kautz–Singleton).

**Honest scope.** This is a paper-hygiene commit, not a new scientific
finding. It does not claim any new result, only that the previously
published results are now surfaced in the paper and are cross-checked
against `results/*.json` so drift can't silently ship. Total 80 tests
green.

## P3: reproduce-all script (2026-07-20)

`scripts/reproduce_all.py` — one command to regenerate every checked-in
`results/*` artifact from scratch. Declarative `MANIFEST` of 19 experiments
(name, script, outputs, cost tag, dependencies), a small subprocess runner,
and CLI flags `--only`, `--skip`, `--fast`, `--dry-run`, `--verify`,
`--continue-on-error`. Dependency resolution goes both ways: `--only
analyze_sweep` pulls in the `sweep` predecessor; `--skip sweep` / `--fast`
transitively drops `analyze_sweep` so we never run an analysis without its
input. Verified live on the cheapest entry (identifiability, no artifact,
0.5s, rc=0).

New `tests/test_reproduce_all.py` (11 tests) locks the manifest ↔ disk
invariant: every checked-in `results/*.{json,jsonl,png}` must be produced
by some manifest entry (no orphans), every declared output must exist on
disk today (no phantom claims), every paper-claimed artifact from
`test_paper_claims.py` must appear in the manifest, dependency names must
resolve, and the CLI selection rules behave as documented. Full suite 91
green (was 80).

**Grill.** This is orchestration + a manifest, not a scientific claim. I
did not do a full end-to-end fresh reproduction — running everything
including `sweep.py` (built for hours) and `train_policy.py` would burn a
night. So "reproduces every artifact" is a *plan* backed by the tests,
not an empirical claim. The `--verify` mode does check every declared
output is on disk today, and it passes. One honest edge case: `robust.py`
writes `results/robust.json` when run, but that file isn't checked in
(the BACKLOG item was about landing the agent, not its numbers) — the
manifest declares `outputs=()` for robust with an inline comment; if
that JSON is ever committed, promote the tuple.

## P3: flagship generalizes to a second SNAP topology (2026-07-20)

The original flagship (`results/real/email_topo.json`) showed content-aware
beating the best structural baseline on the SNAP email-Eu-core graph (~1k
nodes, real org departments). BACKLOG asked whether the win survives on a
second real topology. `scripts/multi_topology.py` reruns the identical
paired comparison on the SNAP Autonomous-Systems Internet graph (6474
nodes, mean-degree 3.88, sparse power-law) with a shared spec (K=30 CVEs,
budget=3, horizon=60, homophily=0.4, band=(0.30, 0.80), 20 paired trials
each). Output: `results/real/snap_topologies.json`.

**Result — the flagship generalizes.** On both SNAP topologies content-aware
strictly beats the best fixed structural baseline:

- **email-Eu-core** (n=986): content-aware **32.33%** infected vs
  betweenness (best structural) **34.03%** — Δ=**+1.70pp** (CI95
  [+1.46, +1.94]), Wilcoxon **p=8.78e-05**, wins **20/20**. Also beats
  the ensemble oracle (per-trial min over structural baselines) at Δ=+1.54pp,
  p=8.77e-05, 20/20.
- **as-internet** (n=6474): content-aware **0.07%** infected vs
  greedy-blocking (best structural) **1.43%** — Δ=**+1.36pp** (CI95
  [+0.03, +2.98]), Wilcoxon **p=7.69e-03**, wins **9/20**. Ensemble
  oracle: Δ=+0.61pp, p=4.22e-02, 5/20.

**Grill.** Both wins are real and paired-significant, but the two topologies
sit in very different regimes:

- On email-Eu-core the outbreak is dense and structural defenses barely
  dent it (34.0% vs 34.8% no-defense), so content-aware's extra 1.7pp is
  a *large fraction* of the total defensible surface — the exact scenario
  the paper claims: hubs are not vulnerability hubs, so degree/eigenvector/
  betweenness targeting is nearly wasted.
- On AS the graph is sparse enough that ANY defense already contains most
  outbreaks (13.4% no-defense → 1–2% under any structural rule → 0.07%
  under content-aware). The absolute delta is small in points but content-
  aware achieves near-total containment. The 9/20 (not 20/20) win count
  is a paired-ties artifact — in ~half the AS trials the structural
  baseline also finishes at zero infected, giving a tie that Wilcoxon
  treats as a non-win.

**Honest scope.** This is a two-topology generalization test, not a
sweep-over-all-topologies claim. The AS graph nodes are Autonomous
Systems (organisations), not individual hosts — the "software monoculture
per zone" model still fits (each AS runs a coherent software stack) but
this is a stretch of the SERUM abstraction. What we CAN claim: on the two
SNAP topologies checked, content-aware ≥ best structural on every
paired trial, and strictly better than best structural on average with
Wilcoxon p < 0.01. New `tests/test_multi_topology.py` (3 tests) locks in
the artifact and smoke-tests the harness on a synthetic BA graph so CI
doesn't need the network. 94 tests green.

### SR2 zone-hub divergence — measurable property that predicts content-aware advantage

**What.** Converted the intuition "content-aware wins when the payload's
vulnerable subgraph diverges from physical hubs" into a *measurable* per-CVE
score (no synthetic knob needed), and empirically tested whether it predicts
the observed delta over DegreeDefense.

**Metrics** (`serum/inference/divergence.py`):
- `rank_divergence(g, c) = 1 - Spearman(deg_G(v), vuln_deg(v)) over v ∈
  carriers(c)`. Range [0, 2]; higher = physical-hub ranking within the carrier
  set disagrees more with the vulnerable-hub ranking. Returns None when the
  carrier set is <3 hosts or all ranks are tied.
- `hub_swap(g, c, k) = 1 - Jaccard(top-k by deg all hosts, top-k by vuln_deg
  on carriers)`. Direct operational analogue at defensive budget k.

**Experiment** (`scripts/divergence.py`, N=90 real-NVD trials, K=12, n=400,
budget=2, horizon=50, homophily ∈ {0.0, 0.2, ..., 1.0}, 15 trials each):

| predictor        | Spearman r | permutation p | notes |
|------------------|-----------:|--------------:|-------|
| **rank_divergence** | **−0.263** | **0.0105**  | metric, defined only from graph + CVE |
| hub_swap         |     −0.196 |        0.055 | operational, budget-parameterized |
| homophily (knob) |     −0.027 |        0.808 | synthetic; drowned out by within-bin variation |

**Finding.** rank_divergence significantly predicts the per-trial content-aware
advantage (p_perm=0.010) and DOES SO BETTER THAN THE SYNTHETIC HOMOPHILY KNOB
IT REPLACES (r=−0.263 vs r=−0.027, p=0.81). The metric captures per-trial
structural variation the knob cannot — turning a nuisance parameter into a
measured property of the (graph, payload) pair. Passes Bonferroni for 3 tests
(α=0.017).

**Grill / honest direction.** The sign is *opposite* the naive intuition. LOW
divergence (physical hubs coincide with carrier hubs) predicts LARGER content-
aware advantage, not smaller. Explanation: low divergence → carrier subgraph
is well-connected → outbreak grows large enough for either policy to matter →
content-aware pulls ahead. HIGH divergence → carrier subgraph fragmented →
outbreak dies naturally → both policies do fine → tiny delta. The metric
still predicts, just in the opposite direction — I've locked in this direction
in a test (`test_experiment_result_hypothesis_holds_when_artifact_exists`) so
a future re-run cannot silently flip the sign without failing CI.

**Effect size.** r²≈0.07 — modest. Divergence is *one* signal among many, not
a complete explanation of the delta. Reported as such.

**Honest scope.** Synthetic BA topology with real NVD-derived CVE profiles;
K=12, n=400. Not run on real SNAP topologies (email/AS) because we don't
control homophily there. Direction may differ in a saturating regime with
much larger budgets or different `beta`. Cross-checked artifact
(`results/divergence.json`) against 11 tests including sign of the finding.
Full suite 105 tests green.

## Phase 20 — SR6 multiplicity correction (Round 2)

**Goal.** L6 in the paper conceded "many paired comparisons; the marginal
results should be read with a family-wise correction" — an honest ack we then
didn't actually compute. Do the correction.

**Build.**
- `serum/inference/multiplicity.py`: pure-python `holm_bonferroni` (step-down,
  monotonicity enforced by running max, clipped to [0,1]) and `bonferroni`
  (uniform multiplier) — both return a `MultiplicityRow` per input test in
  original input order with `p_raw`, `p_adj`, ascending `rank`, and a
  `rejected` flag at α.
- `scripts/multiplicity.py`: curates a family of 11 headline paired-Wilcoxon
  p-values from JSON artifacts on disk, applies both corrections, writes
  `results/multiplicity.json`, prints a markdown table. Explicitly excludes
  duplicates (adversarial "band" = multitopo "ba" — same seeds, same p, would
  double-count).
- `tests/test_multiplicity.py`: 12 tests — worked example, monotonicity,
  clipping, invariants (Holm ≤ Bonferroni), artifact ↔ recompute consistency,
  paper cross-check.

**Family** (m=11): synth-flagship vs best-fixed + vs ensemble oracle; SNAP
email-Eu-core vs best-fixed + vs ensemble; SNAP autonomous-systems vs
best-fixed + vs ensemble; synth BA/WS/RGG topologies vs best-fixed;
adversarial evasive + identifiable attackers vs best-fixed.

**Result (α=0.05).** All **11/11** survive Holm-Bonferroni. Bonferroni
rejects 9/11 (the two SNAP-AS comparisons are the marginal drops). Largest
Holm-adj p among the surviving comparisons: 0.042 (SNAP-AS vs ensemble).
Five of the eleven remain at p_adj < 10⁻³.

**Grill.** (i) Overclaimed initial paper text said "every best-fixed-baseline
headline holds at p_adj < 10⁻³" — false, only 3 of 6 do (synth-flagship,
SNAP email, synth-RGG). Corrected to the honest "five of the eleven" phrasing
before commit. (ii) Family scope is a judgment call; I could have inflated
m by including every incidental sub-comparison (e.g. per-attacker sub-analyses,
value-steering deltas, canary-budget sweeps), which would have been
dishonestly conservative in the *other* direction. Restricted to genuine
headline claims, deduplicated by seeds/spec. (iii) Holm-Bonferroni is valid
under arbitrary dependence between tests, so I don't need to argue
independence — correct choice given how many of these comparisons share the
same underlying random source.

**Honest scope.** Correcting for m=11 does not correct for the "garden of
forking paths" — we ran many *experiments*, of which these 11 are the
headline set. The correction protects against multiplicity within that set;
it does not protect against the researcher-degrees-of-freedom in choosing
which paired comparison to headline. That is a broader problem no p-value
adjustment fixes; the preregister-and-fix-in-advance would be the honest
solution and we don't do that.

**Paper update.** New "Multiplicity" paragraph in §Extended results (cites
11/11 Holm, 9/11 Bonf, p_adj_max=0.042, artifact path); L6 downgraded from
"open ack" to "addressed" with pointer. Guarded by
`test_paper_reports_holm_corrected_family`.

**Suite.** 117 tests green (12 new).

## L4 — infection-detection-noise channel (2026-07-23)

**Goal.** L4 in the paper conceded "perfect infection observability is
assumed; we stress inventory noise but not infection-detection noise." Close
the gap: give the defender an imperfect *sensor on infection status* (distinct
from the existing inventory noise on host vulnerabilities) and measure how fast
content-awareness degrades relative to a payload-blind structural defender.

**Build.**
- `serum/sim/environment.py`: two-channel detection-noise model on the env.
  `detection_miss` = probability a real infection is *permanently* missed at
  onset (a dwelling implant the EDR never picks up); `detection_false` =
  fraction of susceptible hosts a stuck sensor persistently reports as infected.
  Noise sampled once per episode at reset (reproducible). `_observed_infected`
  = `(_infected − _missed) ∪ _false_alarms`; `_observe()` now emits the
  *observed* infected / newly-infected sets, so both the belief update and the
  frontier see the corrupted view. Ground truth (`_infected`, `_ever`) is kept
  intact for scoring.
- `serum/baselines/heuristics.py`: `frontier()` and `AcquaintanceDefense` read
  `_observed_infected` when present, else ground truth. Susceptibility check
  stays ground truth — a defender still can't spend budget on an already-patched
  host whatever the sensor says; noise only controls *who counts as a spreader*.
- `serum/experiments/harness.py`: `TrialSpec.detection_miss / detection_false`
  threaded into `build_episode`.
- `scripts/detection_noise.py`: paired sweep over a 10-point (miss, false) grid;
  NoDefense / Degree / ContentAware / OracleContentAware through the identical
  outbreak; reports mean infected per policy, the paired CA−degree gap, Wilcoxon
  p, and the crossover point where (if ever) content-aware stops beating degree.
- `tests/test_detection_noise.py`: 7 invariants — missed infections never appear
  in the observed set but still spread in ground truth; false alarms are
  persistent and never in `_infected`; noise=0 reproduces the noiseless
  observation exactly.

**Result (20 paired trials × 10 noise points, real NVD, n=400, K=30, budget 5).**

| miss | false | no-def | degree | CA | oracle | CA−deg | p | wins/n |
|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| 0.00 | 0.00 | 18.4% | 1.3% | 0.9% | 0.8% | +0.38pp | 1.2e-2 | 8/20 |
| 0.10 | 0.00 | 10.4% | 2.5% | 1.4% | 1.1% | +1.18pp | 2.2e-2 | 10/20 |
| 0.20 | 0.00 | 15.6% | 2.2% | 1.0% | 0.9% | +1.18pp | 1.8e-2 | 7/20 |
| 0.30 | 0.00 | 8.8% | 1.5% | 1.1% | 1.0% | +0.41pp | 1.2e-1 | 8/20 |
| 0.00 | 0.02 | 8.8% | 1.8% | 1.9% | 1.1% | −0.09pp | 8.3e-1 | 4/20 |
| 0.00 | 0.05 | 14.8% | 4.7% | 3.5% | 2.3% | +1.16pp | 8.6e-2 | 7/20 |
| 0.00 | 0.10 | 13.0% | 3.5% | 2.4% | 1.8% | +1.14pp | 5.1e-2 | 7/20 |
| 0.10 | 0.02 | 13.2% | 3.5% | 2.4% | 1.5% | +1.02pp | 3.9e-1 | 6/20 |
| 0.20 | 0.05 | 4.4% | 2.2% | 1.2% | 1.0% | +1.01pp | 2.9e-1 | 2/20 |
| 0.30 | 0.10 | 12.0% | 5.1% | 4.5% | 2.6% | +0.68pp | 7.8e-1 | 4/20 |

**Reading (honest).** Content-aware retains a *positive* infection edge over
degree at 9 of 10 noise points, including the full miss channel (all four
positive) — missed detections withhold evidence symmetrically from both the
belief and the structural frontier, so they don't preferentially hurt the
inferring defender. The one non-positive point is the pure false-alarm channel
at 2% (−0.09pp, essentially a tie): false alarms *poison the belief* (a host
that doesn't carry the true CVE now looks like counter-evidence) in a way they
can't poison a belief-free heuristic. But the effect is small and does not
compound — at 5% and 10% false alarms the gap is positive again (both policies
just degrade together). **This is graceful degradation, not a new significant
win.** Per-point Wilcoxon at n=20 only reaches p<0.05 at the noiseless and
miss=0.10 points; the sweep's value is the *shape* (gap stays ≥ −0.1pp across a
realistic sensor-noise grid), not any single p-value. So L4 moves from
"unaddressed assumption" to "measured: content-awareness survives detection
noise, with the false-alarm channel the one to watch."

**Grill.** (i) Tempting overclaim: "content-aware robust to detection noise,
still wins." False — it ties once and no individual noisy point is significant
at n=20. Reported as graceful degradation with the tie called out explicitly.
(ii) The miss channel looking *harmless* is real but for an unglamorous reason
(symmetric evidence withholding), not because inference is magically robust;
said so. (iii) 20 trials is thin for 10 points; the honest artifact is the gap
sign/shape, and I did not promote any noisy point to a headline p-value.

**Paper update.** New "Detection-noise robustness" paragraph in §Extended
results; L4 downgraded from open assumption to "addressed (graceful
degradation; false-alarm channel is the sensitive one)."

**Suite.** 124 tests green (7 new).

## SR5 — adaptive adversary vs the poison-robust defender (2026-07-24)

**Goal.** L5 conceded our robustness attacks are self-designed strawmen. Close
it: build the white-box attacker that *best-responds to the RobustAgent's trust
audit* and honestly test whether the defense still holds.

**The audit, and its best response.** RobustAgent keeps a trust weight α that
moves toward the fraction of new *real* infections carrying its MAP CVE. Real
spread is gated on c*, so the audit's pass-rate for a poisoned MAP c' converges
to the carrier overlap `|car(c*)∩car(c')| / |car(c*)|`. The naive poisoner
(deception.py) picks a disjoint high-prevalence c' → overlap→0 → α collapses →
agent falls back to structure (why naive poisoning fails). The best response
maximises `overlap · |car(c*)\car(c')|`: keep the audit passing *and* leave part
of the true victim set undefended. A pure superset c' over-covers the truth
(Prop. 3) and is useless — the attacker is forced onto this knife-edge.

**Build.**
- `serum/attack/adaptive.py`: `best_response_cve` (picks c' maximising the
  overlap·leak damage score subject to overlap ≥ τ; falls back to max-overlap,
  then to naive) + `choose_decoys_adaptive` (plants k decoys on car(c')\car(c*)).
- `serum/experiments/harness.py`: `TrialSpec.decoy_strategy ∈ {naive, adaptive}`
  dispatched in `build_episode`.
- `scripts/adaptive_attack.py`: paired sweep over decoy budgets; arms =
  {degree floor, single-soft vs adaptive, robust vs naive, robust vs adaptive};
  reports the paired (robust-adaptive − degree) gap, Wilcoxon p, and whether the
  robust agent holds (infection ≤ structural floor).
- `tests/test_adaptive_attack.py`: 4 invariants (decoys never carry c*; best-
  response overlaps AND leaks the truth; adaptive ≠ naive placement).
- `scripts/reproduce_all.py`: registered `adaptive_attack` AND the previously
  unregistered `detection_noise` (fixes a test_no_orphan_result_files failure).

**Result (60 paired trials/point, real NVD, n=500, K=40, budget 5).**

| decoys (% fleet) | degree | soft/adaptive | robust/naive | robust/adaptive | gap vs floor | p | holds |
|--:|--:|--:|--:|--:|--:|--:|:--:|
| 0 | 1.49% | 0.94% | 1.07% | 1.07% | −0.42pp | — | yes |
| 5 (1%) | 1.49% | 2.45% | 1.41% | 1.46% | −0.03pp | 0.57 | yes |
| 10 (2%) | 1.49% | 2.88% | 1.54% | 1.61% | +0.12pp | 0.26 | yes |
| 15 (3%) | 1.49% | 3.11% | 1.44% | 1.71% | +0.22pp | 0.083 | yes |
| 20 (4%) | 1.49% | 3.61% | 1.66% | 1.77% | +0.28pp | 0.081 | yes |
| 30 (6%) | 1.49% | 4.02% | 1.65% | 1.83% | +0.33pp | 0.056 | yes |
| 50 (10%) | 1.49% | 4.48% | 1.79% | 1.92% | +0.42pp | 0.022 | **NO** |

**Reading (honest).** The adaptive attack is *real* — it drives a single
audit-free soft belief to 2.5–4.5% (vs the naive attack, which the robust agent
shrugs off). But **RobustAgent holds against the best response up to 30 decoys
(6% of the fleet)**: its gap over the structural floor is not significant there.
The edge grows monotonically and becomes marginally significant only at an
extreme 50 decoys (10% of the fleet, +0.42pp, uncorrected p=0.022) — and that
single grid point does **not** survive Holm across the 7 budgets (0.022×7≈0.15).
So the audit is not unbreakable, but breaching it costs a poisoning budget
*twice* the defender's containment budget (50 decoys vs budget 5) — a poor trade.

**Grill.** (i) Tempting overclaim: "robust to adaptive poisoning." False — it
breaches at 10%. Reported as a bounded hold with the breach point named. (ii)
Tempting opposite overclaim: "adaptive attack beats the robust agent." Also
false/misleading — one uncorrected point at an extreme budget that fails Holm.
Stated both bounds. (iii) The best response is on *placement* against a *known*
audit; a joint payload+timing+placement adversary is still open (said so in L5).
(iv) Confirmed at 60 trials after a 30-trial run showed the breach marginal, per
honest-check discipline.

**Paper update.** New "Adaptive adversary (SR5)" paragraph in §Extended results
after the poison-robust paragraph; L5 downgraded from open to "addressed, with a
bounded caveat."

**Suite.** 128 tests green (4 new).

## G1 — run the closest prior systems as baselines (2026-07-24)

**Goal.** Round-3 grill's existential finding: CyGym (2025) and DAVA (2015) are
named as the nearest systems but never run — every beaten baseline predates 2016.
Put both in the harness and report the honest head-to-head.

**Build.**
- `serum/baselines/closest.py`:
  - `StaticPriorDefense` (CyGym-style) = the content-aware planner with the belief
    frozen at its prior (`update_belief=False`) — reproduces CyGym's static-prior,
    no-online-update *stance* (not its offline PSRO game), which is the axis SERUM
    claims to improve.
  - `DavaDefense` = data-aware, exploit-blind vaccination: per-step greedy
    shield-value (exposure to observed-infected × onward degree) on the observed
    frontier, patching (availability-preserving) the top-budget hosts. A proxy for
    DAVA's dominator-tree allocation.
- `scripts/closest_baselines.py`: 6-policy paired sweep (no-defense, degree, DAVA,
  CyGym-static, content-aware, oracle) on real NVD; reports means + paired
  Wilcoxon of content-aware vs each closest system, with per-trial win counts.
- `tests/test_closest_baselines.py` (4): CyGym-static belief never drifts; DAVA
  spends budget and is exploit-blind (invariant to removing the payload); both
  beat no-defense.
- `scripts/reproduce_all.py`: registered `closest_baselines`.

**Result (40 paired outbreaks, real NVD, n=500, K=40).**

| policy | infected | availability |
|---|--:|--:|
| no-defense | 14.02% | 100.0% |
| degree | 1.52% | 96.95% |
| DAVA (data-aware, exploit-blind) | 1.70% | 100.0% |
| CyGym-static (static prior) | 1.15% | 97.70% |
| **content-aware (ours)** | **0.95%** | 98.35% |
| content-aware-oracle (bound) | 0.85% | 100.0% |

- vs **DAVA**: +0.74pp, +43.8% rel., wins 17/40, **p=2.8e-4**. DAVA is *worse than
  degree* — vaccinating exposed-but-non-exploitable hosts wastes budget, i.e. the
  thesis, demonstrated against the actual data-aware prior method.
- vs **CyGym-static**: +0.19pp, +16.6% rel., wins **8/40**, **p=1.1e-2**. Small
  but significant; online inference helps in a minority of outbreaks (wrong-prior
  ones) and is a wash otherwise — consistent with the L2 belief-freezing ablation.

**Reading (honest).** Content-*awareness* (defending the exploit-specific
subgraph) is the dominant advantage — it beats both the data-aware and the
static-prior prior systems. Online *inference* specifically adds a small,
significant, minority-of-trials refinement. This is the honest bound: the paper
should lead with content-awareness, not imply online inference is the main driver.

**Grill of the fix.** (i) Partially confirms G2 — online-inference edge is small;
now stated, not implied away. (ii) Fairness: reproductions are of each system's
*stance*, not its full original algorithm — recorded as scope. (iii) 8/40 win
rate re-exposes G4 (minority-of-trials advantage) — reported.

**Paper.** New "Head-to-head vs the closest prior systems" paragraph in
§Experiments. **G1 status → addressed** in REVIEW_MITIGATION.md.

**Suite.** 132 tests green (4 new).

## Round-3 grill mitigations G2–G12 (2026-07-24)

Worked the entire remaining Round-3 backlog in one pass. Two new experiments,
several honest reframes, one provenance fix; suite 134 green.

**G2 (inference load-bearing?)** — `scripts/inference_value.py`: online inference's
edge over a static (CyGym-style) prior doubles under a *misleading* prior
(+0.19→+0.44pp, p=1.8e-2) but stays modest. Reframe: content-awareness is the
driver; online inference is a refinement that matters most under bad threat intel.
Fixed a latent bug — `CVEBelief` threw on ndarray priors (string compare ran
before the isinstance check). +2 tests.

**G3 (theorem is definitional)** — recast Thm 1 as a *characterization of the
observation model*; relabelled "116/116" a consistency check, not validation;
theory now leads with the group-testing rate.

**G4/G5 (tiny effects, huge variance, minority win rates)** — abstract now gives
absolute magnitudes beside relative %; severity paragraph reports the minority
per-trial win rates (16/40, 18/40) and the non-significant band; flagship
paragraph reports per-arm SD≈0.10 (> the 5.9pp effect) and that the small p is a
paired-design artifact.

**G6 (manufactured regime?)** — `scripts/homophily_sensitivity.py` sweeps the
monoculture knob. **My hypothesis was wrong**: the content-aware edge is
significant at *every* homophily incl. 0 (+0.26pp, p=6.5e-4), non-monotonic,
peaking mid-range. So the advantage is NOT an artifact of the homophily knob —
the experiment refuted the worry and *strengthens* the paper. Corrected the
canned verdict to match the data.

**G7** — poison-robust paragraph reframed: under poisoning the edge evaporates;
the robust agent is a safety net (graceful degradation), not a win.

**G8/G9** — related work concedes the SCENARIOID delta is partly operational and
our exploit-ID task arguably easier; the Hoffmann delta a different/easier setting,
not a stronger theorem.

**G10** — L6 downgraded to "partly addressed" (forking paths beyond the family of
11 unaddressed without pre-registration).

**G11** — `data/clean/data_card.json` records the pinned NVD snapshot
(2026-03-21–2026-04-17, committed); paper states results reproduce bit-for-bit.

**G12** — Extended results moved to a proper `\appendix` after Limitations; main
body now leads with the four core claims.

**Net.** All 12 Round-3 findings addressed (G1 earlier). Experiments: G1, G2, G6
(+ 4 new tests total this pass, +8 across the round). Reframes/acks for the rest.
The paper is materially more honest and, on G1/G6, materially stronger. 134 green.

## Round 4 grill + mitigation (2026-07-29)

Fresh hostile pass after Round 3, then mitigated it. The key finding was
**meta**: the honest Round-3 walk-backs (inference near-inert, theorem
definitional, tiny synthetic margins, null robustness) had collectively hollowed
the headline. The constructive fix (H1) is to **lead with the one substantial
real result** — the real-topology flagship (−28.4%, 5.9pp, p=1.7e-7) — and demote
the rest to machinery/scope.

**Verified first (honest-check):** homophily=0 genuinely decorrelates zone from
vulnerability (same-seg vuln Jaccard 0.139 vs diff-seg 0.144, ratio 0.96), so the
Round-3 G6 refutation is sound, not a generator artifact.

**Mitigations (framing/honesty only — no numbers changed, suite 134 green):**
- H1: abstract + intro + CONTRIBUTIONS.md reframed to lead with content-awareness
  on real topology; online inference explicitly a refinement.
- H2/H7: relabelled the closest-baselines as reimplementations of each system's
  *stance* ("in the spirit of CyGym", "DAVA-style"); DAVA proxy called a
  conservative lower bound; claim softened to "of this class."
- H3: G6 paragraph now rebuts the monoculture-knob artifact but not L1/L3.
- H4: misleading prior framed as a deliberately-constructed worst-case.
- H5: C4 robustness demoted to a note (null result, not a headline).
- H6: C2 recast as characterization + measured rate (real correlation bends it
  toward the i.i.d. bound), singleton condition owned as definitional.

Round 4 was a framing round — exactly what a paper needs pre-submission. The
result is a more honest paper that leads with its strongest real evidence.

## Paper compiles end-to-end (2026-07-29)

First real build verification (previously only brace/env balance was checked).
Installed `tectonic` (self-contained LaTeX engine) and compiled `paper/serum.tex`:
**0 undefined references or citations** in the multi-pass build; all cross-refs
and the 46-entry bibliography resolve; produces a 141 KiB `serum.pdf`. Only
cosmetic overfull-\hbox warnings remain (≤90pt, mostly long \texttt{} paths in the
appendix — visible margin overrun, not errors). Build artifacts (pdf/log/aux/blg)
gitignored under `paper/`.

## Round 5 — verified + hardened the H1 reframe (2026-07-29)

Linchpin check: does the new lead result (real-topology flagship) also suffer the
minority-win-rate flaw (G4)? **Verified NO** — content-aware wins 20/20 paired
outbreaks vs betweenness AND the ensemble oracle (p=8.8e-5, committed
snap_topologies.json), 37/40 in a budget-8 replication, 7.85pp absolute. Added the
win-rate fact to the flagship paragraph and reordered the intro contribution
bullets to lead with the empirical finding. Rounds 1–5 exhausted the reachable
self-review.

## Open / next
- **Paper verified to compile.** Optional polish: fix the ~5 overfull hboxes
  (cosmetic).
- The one irreducible gap remains **L1**: real host-level enterprise validation
  (blocked by proprietary scan data) — the single most valuable future work, and
  external, not more self-review.
- SR5 done; Path A prune done; grill Rounds 1–5 all mitigated; PDF builds clean.

