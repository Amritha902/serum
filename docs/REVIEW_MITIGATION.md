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
- [x] **G2 — DONE (FIX+REFRAME).** `scripts/inference_value.py`: online inference's
  edge over a static prior roughly **doubles under a misleading prior**
  (+0.19pp→+0.44pp, p=1.8e-2) but stays modest even then. Honest conclusion: online
  inference is a *refinement that matters most under bad threat intel*, not the
  driver — content-awareness is. Paper reframed accordingly (new §"When is online
  inference load-bearing?"). Also fixed a latent bug: `CVEBelief` crashed on
  ndarray priors. 2 tests added.
- [x] **G3 — DONE (REFRAME).** Thm 1 recast as a *characterization of the
  observation model* (the belief's support = the profile intersection by
  construction); the "116/116" agreement relabelled a *consistency check on the
  implementation*, not empirical validation. Theory now leads with the
  group-testing sample-complexity rate. Contribution bullet + §theory + experiment
  paragraph all reworded.
- [x] **G4 — DONE (ACK+REFRAME).** Abstract now gives absolute magnitudes
  (0.6pp / 5.9pp) beside relative %; the severity-scaling paragraph now reports the
  minority per-trial win rates (16/40, 18/40) and the one non-significant band
  (p=0.14) honestly.
- [x] **G5 — DONE (ACK).** Flagship paragraph now reports the per-arm variance
  (SD≈0.10, larger than the 5.9pp effect) and states the small p reflects the
  paired design, not separated marginals.
- [x] **G6 — DONE (FIX; refutes the worry).** `scripts/homophily_sensitivity.py`
  sweeps the monoculture knob. **Surprise:** the content-aware edge is significant
  at *every* homophily incl. 0 (no monoculture: +0.26pp, p=6.5e-4), non-monotonic,
  peaking mid-range. So the advantage is **not** an artifact of the manufactured
  regime — homophily controls only spatial clustering of the vulnerable set, not
  whether it diverges from the hubs. Stated in the paper as a threat the data
  answers. (My initial hypothesis — advantage vanishes at homophily 0 — was wrong;
  the experiment corrected it.)
- [x] **G7 — DONE (REFRAME).** Poison-robust paragraph now states plainly that
  under poisoning the content-aware edge *evaporates* and the robust agent is a
  *safety net* (never worse than structure), i.e. graceful degradation, not a win.
- [x] **G8/G9 — DONE (REFRAME).** Related work now concedes the SCENARIOID delta is
  partly operational (online-vs-offline) and our exploit-ID task is arguably
  *easier* (categorical label under hard consistency); and that the Hoffmann delta
  is a *different, easier* setting (observable vs latent), not a strictly stronger
  theorem.
- [x] **G10 — DONE (ACK).** L6 downgraded to "partly addressed": correcting within
  the family of 11 does not fix forking paths across all experiments nor the choice
  of which 11 to headline; only pre-registration would.
- [x] **G11 — DONE (FIX).** `data/clean/data_card.json` now records the pinned
  snapshot (NVD 2.0, published 2026-03-21–2026-04-17, committed); paper states all
  real-data results derive from this committed snapshot, reproducible bit-for-bit.
- [x] **G12 — DONE (REFRAME).** Extended results moved to a proper `\appendix`
  after Limitations, retitled "Extended results and honest negatives" with a
  lead-in noting the main body is the four core claims. Main body now leads with
  the leads, breadth demoted to appendix.

**Round-3 net:** all 12 findings addressed. G1/G2/G6 were experiments (and G6
*refuted* its own premise); G3/G7/G8/G9/G10/G12 reframes; G4/G5 honesty edits;
G11 provenance. Suite 134 green. The paper is materially more honest and, on G1
and G6, materially *stronger*.

---

# Round 4 — post-mitigation grill (2026-07-29)

The Round-3 mitigations were individually honest; a fresh hostile pass asks what
they *cost*. Second-round penalties dominate. The verified fact carried in:
homophily=0 genuinely decorrelates zone from vulnerability (same-seg vuln
Jaccard 0.139 vs diff-seg 0.144, ratio 0.96), so the G6 refutation is sound.

## Existential (meta)

**H1 — The honest walk-backs have hollowed out the headline.** Tally after Round 3:
C1 online inference buys ~0.19pp on a minority of trials (G2); C2's "theorem" is
self-described as definitional with a circular check (G3); C3's synthetic-CVE win
is 0.6pp absolute with a 16/40 minority win rate and outcome SD > effect (G4/G5);
C4 robustness is "no worse than degree" (G7). A PC skimming the now-honest paper
sees a method that wins a minority of outbreaks by a fraction of a point, whose
theory is a definition, whose inference is nearly inert, and whose robustness is a
null result. **Each mitigation was right, but collectively the paper has argued
itself out of every headline.** → **[REFRAME]** There IS one substantial, real
result left: the real-topology flagship (SNAP email-Eu-core, real departments,
real CVEs) where structure-only barely helps (17.6% vs 20.1% no-defense) and
content-aware cuts to 11.7% — **−28.4%, 5.9pp absolute, p=1.7e-7**. Lead the paper
unambiguously with THAT; state in the abstract that the synthetic-CVE edge is
small and the value shows up when vulnerable zones diverge from hubs (real org
structure). Reframe the thesis from "online inference" to "content-awareness on
real topology."

## Major (second-round penalties)

**H2 — The "closest systems" are self-defined proxies, not the real systems (penalty
of G1).** CyGym-static is literally our own agent with `update_belief=False` — an
ablation of ourselves relabeled as the competitor; DAVA is a per-step shield-value
proxy, not the dominator-tree algorithm. "Beats CyGym and DAVA" rests on our own
reimplementations of their *stance*. → **[REFRAME/ACK]** relabel throughout as "a
static-prior defender in the spirit of CyGym" and "a DAVA-style data-aware
allocator"; soften "beats CyGym/DAVA" to "beats a static-prior / data-aware
defender of this class." Note the originals' released code as the fair follow-up.

**H3 — G6 rebuts the knob-artifact worry but NOT the semi-synthetic critique.**
homophily=0 removes spatial zone-correlation (verified), but the assignment is
still MODELED (popularity-weighted), not a measured host inventory. Risk: reading
G6 as escaping L1/L3. → **[ACK]** state in the G6 paragraph that homophily-
invariance rebuts the monoculture-knob artifact but leaves the semi-synthetic-
assignment limitation (L1/L3) fully intact.

**H4 — The misleading prior (G2) is itself a manufactured regime (penalty of G2).**
We invented a prior peaked on the wrong CVE to show inference helps — and even
then it is +0.44pp. A reviewer: "manufactured a bad prior to rescue the inference
contribution." → **[ACK]** frame explicitly as "under adversarially-misleading
intel," not as evidence online inference is generally important.

## Moderate

**H5 — C4 robustness is a null result presented as a contribution.** "Graceful
degradation, never worse than degree" is, at a top venue, a non-result. →
**[REFRAME]** demote C4 from the four headline claims to a robustness *note*;
state honestly it shows poisoning does not make content-awareness counterproductive
— not that the method is robustly superior under attack.

**H6 — The theory contribution (C2) is thin after G3.** C2 now = a definition + the
observation that ID takes ~log₂K infections (a standard group-testing bound). →
**[REFRAME]** the genuinely non-trivial empirical content is that REAL profile
correlation makes the rate deviate from the i.i.d. bound (median hosts/log₂K ≈
1.02 on real NVD vs ≈2.0 on a Zipf toy). Reframe C2 as "a characterization plus an
empirically-measured sample-complexity rate that real correlation bends away from
the i.i.d. group-testing bound," not a headline theorem.

**H7 — DAVA underperforming degree (1.70 vs 1.52) hints my DAVA proxy may be weak
(compounds H2).** If DAVA is under-implemented, "content-aware beats DAVA" is
hollow. → **[ACK]** note the DAVA proxy is a conservative lower bound on DAVA's
strength; a stronger allocator might narrow the gap.

## Cosmetic

**H8 — Experiment sprawl (~30 scripts, large appendix).** Reinforces G12; the
appendix is now very long. → cosmetic; consider a one-table summary of appendix
results.

## Ranked verdict

H1 is the real issue and is constructive, not fatal: the mitigations exposed that
the paper must **lead with its one strong, real-data result** and honestly demote
the rest. H2–H4 are honesty relabels of the Round-3 fixes. H5/H6 right-size two
over-sold contributions. None require new experiments — Round 4 is a
framing/honesty round, which is exactly what a paper needs before submission.

## Mitigation status (Round 4)

- [x] **H1 — DONE (REFRAME).** Abstract + intro now lead with content-awareness on
  real topology (−28.4%, 5.9pp, p=1.7e-7) and explicitly call online inference a
  refinement "that matters most under misleading intel." CONTRIBUTIONS.md revised:
  new lead sentence + lead order C3→C2→C1→robustness note.
- [x] **H2 — DONE (REFRAME/ACK).** Head-to-head retitled "defenders in the spirit of
  the closest systems"; relabelled a "static-prior defender in the spirit of CyGym"
  and a "DAVA-style data-aware allocator"; claim softened to "beats a defender of
  this class," with the released-code port named as the fair follow-up.
- [x] **H3 — DONE (ACK).** G6 paragraph now states homophily-invariance rebuts the
  monoculture-knob artifact but leaves L1/L3 (semi-synthetic assignment) intact.
- [x] **H4 — DONE (ACK).** Misleading-prior paragraph flags the prior as
  deliberately constructed (worst-case intel), not evidence inference is generally
  important.
- [x] **H5 — DONE (REFRAME).** C4 demoted to a "robustness note" in CONTRIBUTIONS.md
  with an explicit "why demoted: null result" banner.
- [x] **H6 — DONE (REFRAME).** C2 recast as "characterization + measured
  sample-complexity rate" (real correlation bends the rate toward the i.i.d. bound,
  ~1.02·log₂K vs ~2.0 on a Zipf toy); singleton condition owned as definitional /
  1960s separating-systems combinatorics.
- [x] **H7 — DONE (ACK).** Head-to-head scope note calls the DAVA-style allocator a
  conservative lower bound on DAVA's strength.
- [ ] H8 — (cosmetic) appendix summary table — deferred (low value).

**Round-4 net:** all substantive findings (H1–H7) addressed; framing/honesty only,
no numbers changed, suite 134 green. The paper now leads with its one strong,
real-data result and is honest that the rest is machinery, scope, and a null
robustness result. Verified en route: homophily=0 truly decorrelates zone from
vulnerability (Jaccard ratio 0.96), so the G6 refutation is sound.

---

# Round 5 — sanity check on the Round-4 reframes (2026-07-29)

A short pass asking whether "lead with the real-topology flagship" (H1) is itself
sound. The linchpin worry: if the flagship *also* wins only a minority of paired
trials (like the synthetic-CVE regime, G4), then leading with it just relocates
the flaw.

**Verified — the opposite is true.** On the real topology the content-aware agent
wins **20/20** paired outbreaks vs betweenness *and* vs the ensemble oracle
($p=8.8\times10^{-5}$, committed `results/real/snap_topologies.json`), and **37/40**
in a fresh budget-8 replication. So the lead result is a strong-majority,
large-absolute-margin effect (7.85pp) — exactly the result that does NOT have the
minority-win-rate problem. H1 is not just defensible; the flagship is the right
thing to lead with.

**Action taken:** added the win-rate fact to the flagship paragraph and reordered
the intro contribution bullets to lead with the empirical finding (completing H1).
No new existential holes; the Round-4 reframes hold. The remaining honest gaps are
unchanged (L1 real host-level data; the synthetic-regime margins are small — now
correctly framed as regime analysis, not the headline).

**Verdict:** Rounds 1–5 exhausted the reachable criticisms. The paper is honest,
leads with its strongest real evidence, and the one irreducible limitation (L1) is
stated up front. Further grilling yields diminishing returns; the highest-value
remaining work is external (a real host-level inventory), not more self-review.
