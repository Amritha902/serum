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
