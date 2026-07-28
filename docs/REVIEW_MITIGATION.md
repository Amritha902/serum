# SERUM — Hostile IEEE Panel Review & Mitigation Plan

A deliberately harsh mock review (as an IEEE S&P / CNS / IMC panel would write it),
followed by a mitigation for each point: **[FIX]** = build/experiment to remove it,
**[REFRAME]** = scope/positioning change, **[ACK]** = genuine limitation to state
honestly in a Limitations section. Worked top-down; status updated as mitigated.

## A. Threat model & realism (the sharpest attacks)

**R1 — Perfect infection observability.** The defender is assumed to see exactly
which hosts are infected, in real time. Detection is itself hard and noisy; this
assumption does a lot of unearned work.
→ **[FIX+ACK]** Add detection noise (miss/false infection observations) as a
robustness axis, like we did for inventory; show graceful degradation. State the
residual assumption honestly.

**R2 — Toy attacker.** Single CVE, fixed β, synchronous SI/SIR, no scanning
strategy, no C2, no polymorphism. Real worms are multi-exploit and adaptive.
→ **[FIX]** Multi-exploit / polymorphic payload (hidden state = exploit *set*),
already on the backlog; **[ACK]** scanning/C2 out of scope (we model the
epidemiological layer, not the wire protocol).

**R3 — No real malware, no emulation.** Pure probabilistic sim; no Mininet/ns-3,
no packet traces, no real deployment.
→ **[ACK+REFRAME]** Position as an epidemiological/decision-theoretic study
(like the RLGN / network-epidemics line), not a systems paper; add an
emulation-bridge as explicit future work. This is a real scope limit.

## B. Evaluation (where a networking reviewer lives)

**R4 — Scale.** n≈500–1000. Real fleets are 10⁴–10⁶. No scalability/timing study.
→ **[FIX]** Run at n=2k–5k and report wall-clock; show the result and the
inference cost scale.

**R5 — "Real data" is semi-synthetic.** CVE profiles are *assigned* by a model
(NVD product popularity + homophily), not measured on real hosts. The "real"
claim is partly overstated.
→ **[REFRAME+ACK]** Call it "NVD-grounded" not "real host inventories"; be
precise that topology is real, CVE catalog is real, host↔CVE mapping is modeled.

**R6 — The flagship topology is an EMAIL graph.** email-Eu-core is a *social /
communication* graph. Worms do not spread over email-acquaintance edges; they
spread over network reachability. Using it as the host network is a modeling
mismatch a networking panel will pounce on.
→ **[FIX — highest priority]** Re-run on a real *computer-network* topology
(SNAP Autonomous-Systems / router graph). Keep email-Eu-core only as a
"community-structure" ablation, clearly labeled.

**R7 — Crude cost/availability metric.** Availability = fraction-not-isolated
ignores host criticality, patch cost, and false-positive cost.
→ **[FIX]** Cost & blast-radius objectives with host criticality weights
(backlog P0).

**R8 / R10 — Baselines are from the wrong field; no CyGym.** All baselines are
network-science immunization; no comparison to security systems (microsegmentation,
MTD, RL defenders) or to the closest system, CyGym.
→ **[FIX partial]** Add a segmentation/quarantine-style security baseline and the
oracle-after-delay (done). **[ACK]** CyGym uses a different action/observation
model; a fair head-to-head needs a port — state as future work, keep the prose
distinction crisp.

**R9 — Sub-percent margins.** 0.9% vs 1.5% is a real-topology-dependent, tiny
absolute gap on synthetic profiles.
→ **[REFRAME]** Lead with the *real-topology* result (11.7% vs 17.6%, large and
significant) and the *Pareto/robustness* story; present synthetic margins as
regime analysis, not the headline.

## C. Novelty (the program-committee attack)

**R11 — Propagation model not novel.** Multitype percolation. Modeling
contribution ≈ 0.
→ **[REFRAME]** We already concede this; the contribution is the *defender-side
inference + containment*, not the model.

**R12 / R14 — The theorem is elementary AND doesn't drive the result.** Our own
grill shows the belief rarely identifies the CVE and uniform prior works nearly as
well; the identifiability theorem is then decorative.
→ **[REFRAME]** Reframe honestly: the theorem characterises *when identification
is possible* and grounds the group-testing view; the *containment* thesis is
"defend the observation-consistent vulnerable set, which needs no identification."
Two separate, honestly-scoped claims.

**R13 — Group testing makes the theorem old.** Once framed as separating systems,
Thm 1 is 1960s combinatorics.
→ **[REFRAME]** Own it: the novelty is the *online, graph-induced, adversarial*
instantiation (tests realised by contagion, not designed), not the separating
condition itself.

## D. Theory rigor

**R15 — Theorem assumes an idealized world** (noiseless, known seeds, saturating,
perfect inventory) the experiments don't live in.
→ **[ACK]** State assumptions explicitly; note the empirical inference operates
under violations and the containment result does not depend on full identification.

**R16 — No policy guarantees.** The content-aware agent is a heuristic; no
optimality/approximation bound.
→ **[ACK+FIX-lite]** Add the submodular / greedy VoI framing (group-testing
adaptive) as the principled backing; a formal bound is future work.

## E. Focus & presentation

**R17 — Learned policy adds nothing** (matches hand-designed).
→ **[REFRAME]** Keep only as a *validation* ("learning rediscovers the belief
features"), not a contribution; or cut to appendix.

**R18 — "Agentic AI" is thin** (offline heuristic prior, no real LLM).
→ **[REFRAME]** Drop the LLM from the headline; present the CVSS-derived prior as
a cold-start prior, LLM as optional. (User already said the LLM angle is "too
much.")

**R19 — Kitchen sink / unfocused.** 12 novelties, several incremental or negative.
→ **[REFRAME]** One-thesis paper: *content-aware containment via
observation-consistent vulnerable-subgraph defense, robust because confusers
share victims.* Everything else → analyses/appendix.

**R20 — Claims keep getting walked back.** (A symptom of honest grilling.)
→ **[REFRAME]** Freeze a single defensible thesis and one flagship result; state
scope up front.

## Mitigation outcomes (honest)

**R6 — DONE, and it scoped the paper.** Ran on a real SNAP Autonomous-Systems
Internet topology (6474 nodes, `topology='as'`). Result: content-awareness gives
**no benefit** there (−1.7%, p=0.32) — the AS graph is hub-dominated, so
structure-only hub-immunization already contains the worm to 0.1% (no-defense is
only 7.5%). **Honest scope, stated up front:** content-awareness helps on
*segmented/enterprise networks where vulnerable zones diverge from topological
centrality* (email-Eu-core departments: +28%, p=1.7e-7), and is *unnecessary* on
hub-dominated backbone topologies where structure-only suffices. Reporting where
the method does NOT help is the credible answer to R6, not a topology cherry-pick.
This also mitigates R4-scale (ran at 6474 nodes, ~20s/20 trials).

## Round 2 — what the revised paper now exposes (post-mitigation penalties)

**SR3 (existential, self-inflicted).** The honest reframe "containment does not
need identification" deflates the technical core: a POMDP + identifiability
theorem + group-testing framing, then containment works without narrowing the
belief. Reviewer: reduce it to "patch hosts sharing a profile with the infected"
— where is the contribution?
→ **Mitigation (real work):** find the regime where identification *does* drive
containment — heterogeneous inventories where the *consistent-set* vulnerable
subgraph diverges from the *true* one, so a wrong-but-consistent belief mis-defends
and the agent must actually narrow. If such a regime exists and is realistic, the
inference earns its keep; if not, honestly down-scope to "the simple method" and
prove it beats the obvious alternatives. (Backlog P0.)

**SR1 (scoping is a retreat).** Applicability now needs "software-monoculture
zones that anti-correlate with centrality." Is there a REAL enterprise network
with REAL host-vuln data that satisfies this?
→ **Mitigation:** obtain/argue a real enterprise-inventory dataset; or measure
the favorable-regime condition and show where real networks fall. (Backlog P1.)

**SR2 (the win is a knob).** The advantage is a function of `homophily`, set by us.
→ **Mitigation:** chart advantage vs a zone–hub *divergence* metric; locate real
networks on that axis. Makes the knob a measured property, not a free parameter.

**SR5 (self-designed attacks).** Robustness is vs attacks we built with our
parameters; no adaptive adversary targeting the robust agent.
→ **Mitigation:** an adaptive attacker that best-responds to the robust agent's
audit rule.

**SR6 (multiplicity).** Many p-values, no correction.
→ **Mitigation:** DONE — `serum/inference/multiplicity.py` implements Holm-
Bonferroni step-down; `scripts/multiplicity.py` curates the 11 headline paired
comparisons (synth-flagship ×2, SNAP email-Eu-core ×2, SNAP AS ×2, BA/WS/RGG
synth topologies, adversarial evasive/identifiable) — duplicates removed. At
α=0.05: Holm rejects **11/11**, Bonferroni rejects 9/11 (SNAP-AS drops both);
largest Holm-adjusted p among survivors = 0.042. Every best-fixed-baseline
headline holds at p_adj < 10⁻³. Paper §Extended results now has a
Multiplicity paragraph, and Limitation L6 is downgraded to "addressed".
Artifact: `results/multiplicity.json`. Guarded by `tests/test_multiplicity.py`
(12 tests).

**SR7 (time-dependent data).** NVD snapshot depends on fetch date.
→ **Mitigation:** pin a dated NVD snapshot in the repo; version it.

**SR8 (muddled arc).** After the walk-backs, the positive takeaway is fuzzy.
→ **Mitigation:** one-thesis rewrite around whatever survives SR3.

## Mitigation status

- [x] R6 — real AS topology run; honest scope established (segmented nets only).
- [x] R4 — ran at 6474 nodes (13× the earlier scale) with timing.
- [ ] R4 — scale to n=2k–5k + timing
- [ ] R7 — cost & blast-radius
- [ ] R1 — detection noise
- [ ] R2 — multi-exploit
- Reframes (R5, R9, R11–R14, R17–R20) folded into the paper's framing pass.
- Acks (R3, R15, R16, CyGym) go in a Limitations section.

---

# Round 3 — results & closest-prior-work grill (2026-07-24)

A maximally hostile PC pass focused where the author asked: (1) do the headline
*numbers* support the contribution, and (2) has the *closest prior work* already
done this? Every point is grounded in a committed artifact. Ranked
existential → cosmetic. Fixing is deferred to the `mitigate` skill.

## Existential

**G1 — The closest systems are never run; every beaten baseline predates 2016.**
The paper names CyGym (2025) as "THE nearest system" (`paper/serum.tex`,
Related work) and DAVA (Zhang & Prakash 2015) as "the nearest data-aware
method," yet **neither appears in a single results table**. Every baseline
actually beaten — degree, betweenness, eigenvector, acquaintance,
greedy-blocking (`results/real/email_topo.json` keys) — is a structure-only
heuristic from 2002–2016, none content- or data-aware. A PC reads this as:
"authors clear a field of deliberately weak baselines and merely *argue*
superiority over the one system that matters." Positioning prose is not an
experiment. → **[FIX]** implement CyGym's static-zero-day-prior defender and
DAVA (data-aware, conditions on observed-infected subgraph) in the harness and
run them head-to-head on the same paired outbreaks. If CyGym cannot be
reimplemented, the "we fill the online-inference gap CyGym leaves" claim must be
downgraded from a demonstrated result to a conjecture.

**G2 — The paper's own ablation (L2) says the headline contribution is nearly
irrelevant.** The conceptual lead is *online inference of the exploit* (C1).
Limitation L2 concedes that freezing the belief at its prior costs only
**0.1–0.2 points**. So the online inference — the entire novelty of C1 — is
empirically almost inert for the containment win; what remains is "apply a known
immunization score to the (observation-consistent) vulnerable subgraph," which
is DAVA-adjacent and not novel. The paper refutes its own thesis in its
Limitations. → **[FIX]/[REFRAME]** either exhibit a regime where inference is
load-bearing (a payload that shifts `c*` mid-outbreak; genuine cold-start with no
prevalence prior; multi-wave campaigns) and make *that* the headline, or drop the
inference framing and sell the identifiability characterization + Pareto honestly.

**G3 — The identifiability "theorem" is a restatement of the observation model,
and its "100% validation" is circular.** The belief update zeroes posterior mass
on any CVE absent from an infected host's profile (`serum/inference/belief.py`).
Hence the surviving support *is*, by construction, the intersection of infected
profiles. "Theorem 1: identifiable iff the intersection is a singleton" is
therefore definitional, not a derived result. The reported "116/116 = 100%
agreement between the Bayesian belief and the theorem" checks the belief against
itself — the same set intersection computed twice — so it validates nothing. →
**[REFRAME]** present Prop 1/Thm 1 as a *characterization/definition* of the
observation model, not a theorem with empirical support. The only non-tautological
content is the group-testing sample-complexity *rate* (median 5 ≈ log₂K); lead
with that and stop citing "100% validated" as evidence.

## Major

**G4 — The headline effects are a few hosts, and you lose the majority of
individual matchups.** Real-NVD flagship: 0.9% vs 1.5% = **0.6pp ≈ 3 hosts** on
n=500. Worse, the prevalence sweep (`results/prevalence_curve.json`): in 3 of 5
bands content-aware wins **fewer than half** the paired trials — 16/40, 18/40,
12/40 — and the [0.3,0.4] band is **not significant (p=0.139)**, yet all are
sold as "significant relative reductions." A mean advantage driven by a minority
of heavy-tailed wins, while losing most head-to-head matchups, is precisely the
rigor failure a PC pounces on. → **[ACK]+[REFRAME]** report per-trial win rates
next to every mean; stop leading with relative-% reductions on sub-1% absolute
infection numbers.

**G5 — The real-topology flagship's variance dwarfs its effect.** email-Eu-core
(`results/real/email_topo.json`): content-aware **0.117 ± 0.103**, betweenness
**0.176 ± 0.101**. Each arm's SD is ~90% of the content-aware mean and ~1.7× the
effect size (5.9pp). The p=1.7×10⁻⁷ is real but rides entirely on paired
within-trial correlation; the marginal outcome distributions overlap almost
completely (outbreaks swing ~2%→~40%). Statistical significance ≠ operational
guarantee. → **[ACK]** report outcome quantiles/distributions, not just means;
discuss the variance a defender actually faces.

**G6 — You manufacture the favorable regime, then report winning in it.** The
condition the method needs (vulnerable zones misaligned from hubs) is produced by
the software-monoculture zone assignment governed by a `homophily` knob the
author sets; even on email-Eu-core the host↔CVE mapping is modeled, not measured
(L3). This is assuming the conclusion. `serum/inference/divergence.py` already
shows the advantage tracks zone-hub divergence — which cuts both ways: it is also
proof the win is a function of a dialed-in parameter. → **[ACK]** (L1/L3) but the
PC weights this near-existential until real host-level data exists; add a
sensitivity curve showing the advantage → 0 as homophily → 0, presented as a
threat, not a feature.

**G7 — C4 "robustness" is "our method degrades to no better than a trivial
heuristic."** Under the adaptive poisoner (`results/adaptive_attack.json`),
content-aware's gap over plain degree is **+0.12 to +0.42pp (worse)**, and
"robust holds" only means "not significantly worse than degree." So the honest
statement is: under a realistic poisoning attack, the content-aware advantage
*evaporates* and the agent is at best tied with 2002-era degree immunization
(robust_naive 1.41% vs degree 1.49% even at 5 decoys). A safety net sold as a
strength. → **[REFRAME]** state plainly that poisoning erases the content-aware
edge; position the robust agent as graceful degradation, not a win.

## Moderate

**G8 — Novelty vs SCENARIOID (KDD 2023) is an engineering delta, not a research
one.** "Online vs offline" is an implementation choice, and the "identifiability
guarantee" differentiator is definitional (G3). SCENARIOID classifies arbitrary
scenarios from partial cascades — arguably a *harder* inference problem than
recovering a categorical label by set-intersection under a hard consistency
model. A PC may read SERUM's inference as an easier special case, not a
generalization. → **[REFRAME]** state precisely what is harder/new, or concede
the task is easier-but-security-relevant.

**G9 — Novelty vs Hoffmann et al. (ICML 2020) is overstated.** "Observable
attributes vs latent edges" is true, but observability is exactly what makes the
problem easy; Hoffmann's difficulty comes from latency. Removing the hard part is
a weaker problem, not a stronger theorem. → **[REFRAME]**.

**G10 — Multiplicity correction covers only 11 hand-picked headlines.** Dozens of
experiments were run; correcting within a chosen family of 11 does not address
the garden of forking paths across all of them (SR6's own scope note concedes
this). Selecting which 11 to correct is itself a researcher degree of freedom. →
**[ACK]**.

**G11 — NVD snapshot date-dependence (SR7 still open).** Results depend on an
unpinned NVD fetch date; not reproducible bit-for-bit by a third party. →
**[FIX]** pin and version a dated NVD snapshot in the repo.

## Cosmetic

**G12 — Kitchen-sink breadth undercuts the prune.** `docs/CONTRIBUTIONS.md`
distills four claims, but `paper/serum.tex` still carries all 12 novelties and
10+ extended results, diluting reviewer attention across attack surfaces the
prune was meant to retire. → **[REFRAME]** enforce the four-claim prune in the
paper body; push the rest to an appendix.

## Second-round penalties (mitigations that opened new holes)

- The **detection-noise** and **adaptive-adversary** additions (L4/SR5), while
  honest, both landed as *graceful-degradation / no-significant-win* results —
  they enlarge the "content-aware advantage is fragile" narrative (G7) more than
  they shore up robustness. Net effect on the pitch is ambiguous.

## Ranked verdict

Existential (G1–G3) must be answered before submission: **run the closest
systems (G1)**, **prove inference is load-bearing or drop it (G2)**, **stop
calling the definitional condition a validated theorem (G3)**. G4–G7 are
accept-blocking rigor/honesty issues that are mostly fixable by reporting the
numbers you already have more honestly. G8–G12 are positioning/cleanup.

## Mitigation status (Round 3)

- [x] **G1 — DONE.** Implemented both closest systems (`serum/baselines/closest.py`)
  and ran them head-to-head (`scripts/closest_baselines.py`, 40 paired real-NVD
  outbreaks). **Content-aware beats both:** vs DAVA (data-aware, exploit-blind)
  +0.74pp / +43.8% / p=2.8e-4 (DAVA is even worse than degree — vaccinating
  exposed-but-non-exploitable hosts wastes budget, i.e. the thesis); vs
  CyGym-static (static prior, no online update) +0.19pp / +16.6% / p=1.1e-2,
  winning only 8/40 individual trials. Paper §Experiments gains a "Head-to-head
  vs the closest prior systems" paragraph; 4 tests added; suite 132 green.
  *Self-grill of the fix:* (i) it **partially confirms G2** — the online-inference
  edge over a static prior is genuinely small (0.19pp, minority of trials); we now
  state this honestly rather than implying online inference is the main driver.
  (ii) **Fairness caveat (new, minor):** CyGym-static reproduces CyGym's static-
  prior *stance*, not its offline PSRO game; DAVA is a per-step shield-value proxy,
  not the exact dominator-tree — a reviewer could ask for the originals. Recorded
  as scope, not hidden. (iii) The 8/40 and 17/40 win rates re-expose **G4** (mean
  advantage on a minority of trials) — reported, not smoothed.
- [ ] G2 — find the inference-load-bearing regime, or reframe off inference
- [ ] G3 — reframe Thm 1 as characterization; lead theory with the GT rate
- [ ] G4 — report per-trial win rates; drop relative-% on sub-1% numbers
- [ ] G5 — report outcome distributions/quantiles on the flagship
- [ ] G6 — homophily→0 sensitivity curve as a stated threat
- [ ] G7 — reframe C4 as graceful degradation, not robustness win
- [ ] G8/G9 — sharpen or concede the SCENARIOID/Hoffmann deltas
- [ ] G10 — ACK forking-paths beyond the family of 11
- [ ] G11 — pin a dated NVD snapshot
- [ ] G12 — enforce the four-claim prune in serum.tex
