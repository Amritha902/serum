# SERUM — Research Design & Novelty Register

**SERUM** — *Semantic Epidemic Response under Unknown Malware.*
A research program on **content-aware, agentic containment of malware
propagation** under an **unobserved payload**. This document is the living
design spec: the thesis, the formal problem, the finalized feature set, the
novelty register (the paper's contributions), the evaluation protocol, and the
milestones. It is meant to be edited as the work evolves.

> **One-sentence thesis.** A defender that *infers and reasons about what is
> spreading* — the payload's target vulnerability — contains a network worm
> far more efficiently, and with far less collateral disruption, than one that
> sees only network structure; and this holds even when the payload is never
> directly observed.

---

## 1. Problem formalization — the SERUM POMDP

- **Hosts & topology.** A graph `G = (V, E)`; each host `v` carries a software
  vulnerability profile `X(v) ⊆ C`, the set of CVEs it is exploitable by, over
  a CVE universe `C`. Prevalence over `C` is heavy-tailed.
- **Payload (hidden state).** The attacker releases a worm exploiting an
  unknown target `c* ∈ C` with per-contact transmissibility `β`. The defender
  never observes `c*` directly.
- **Vulnerability-gated dynamics.** An infected host `u` infects a susceptible
  neighbour `v` at rate `β` **only if `c* ∈ X(v)`**. Thus the *effective*
  propagation graph is the vulnerable subgraph `G[c*]` induced by carriers of
  `c*` — a payload-specific subgraph of `G`, not `G` itself.
- **Observation.** At each step the defender sees the infected set and the
  static inventory `X`, but not `c*`. Because propagation is gated, every
  non-seed infected host is a *hard constraint*: `c*` must lie in its profile.
- **Actions (budget `B`/step).** `patch(v)` (immunize `v` against the believed
  CVE; availability-preserving), `isolate(v)` (remove `v`; costs availability),
  `segment(u,v)` (cut a link).
- **Objective.** Minimize a multi-objective cost: final/peak infected fraction
  **and** availability loss **and** time-to-containment, under the budget.

This is a **partially observed stochastic control problem where the hidden
state is the exploit**, and the belief over it is what unlocks content-aware
action. That framing is the spine of every contribution below.

---

## 2. Finalized feature set

Legend: **[v1]** implemented tonight · **[v2]** next · **[v3]** stretch.

### 2.1 Simulation core
- Topologies: Barabási–Albert, Watts–Strogatz, random-geometric, Erdős–Rényi **[v1]**;
  real SNAP AS graphs, RocketFuel, enterprise multi-tier (DMZ/LAN/OT segments) **[v2/v3]**.
- Vulnerability profiles: synthetic heavy-tailed (Zipf prevalence, Poisson load) **[v1]**;
  **NVD/CVE-grounded** profiles from real software distributions **[v2]**.
- Spread: gated SI **[v1]**; SIR/SIS with reinfection & patch-then-reexpose **[v2]**;
  per-edge `β` derived from CVSS attack-vector/complexity **[v2]**.
- Seeding: vulnerable random seeds **[v1]**; targeted/hub seeds, multi-cluster **[v2]**.

### 2.2 Payload models
- Single-CVE **[v1]**; multi-CVE / exploit-set worms **[v2]**;
  polymorphic (mutating target over time) **[v3]**; adversarial/evasive **[v2/v3]**.

### 2.3 Inference (the hidden-state tracker)
- Consistency-constrained posterior with prevalence prior **[v1]**;
  **CVSS/text-grounded prior** (language → prior over `c*`, `β`) **[v2]**;
  belief over exploit *sets* (combinatorial) **[v2]**;
  particle filter for large `|C|` **[v3]**;
  **value-of-information probing** (active sensing) **[v2]**.

### 2.4 Defenders (policies)
- Baselines: random, degree, betweenness **[v1]**; eigenvector, greedy
  influence-blocking, acquaintance immunization **[v1.5]**.
- **Content-aware analytic agent** (belief-weighted exposed-vulnerable degree;
  adaptive isolate→patch) **[v1]**.
- **Learned GNN policy** over belief-augmented state (RL) **[v2]**.
- **LLM tool-use agent** that reads threat intel and calls containment
  primitives, with the Bayesian tracker as memory **[v2/v3]**.

### 2.5 Attacker
- Fixed strategies (popular/stealth/random) **[v1]**; adaptive to the observed
  defense **[v2]**; **Stackelberg optimizer** that designs payload+seeds to
  defeat the inference **[v3]**.

### 2.6 Metrics & experimental infrastructure
- Infected fraction, availability, time-to-containment, budget efficiency,
  outbreak-curve AUC **[v1]**; identification accuracy & latency, Pareto fronts **[v2]**.
- Paired-trial harness, parameter sweeps, ablations, seeded reproducibility,
  JSONL logging **[v1]**; bootstrap CIs + paired significance tests, phase
  diagrams **[v1.5]**.

---

## 3. Novelty register — the contributions

Ten contributions, ordered from the conceptual core outward to the ambitious
frontier. Each: **Claim** · **Why it's novel** · **How we demonstrate it** ·
**Risk & mitigation** · **Status**.

### N1 — Vulnerability-gated propagation: "the network is not the propagation graph"
- **Claim.** A spread model in which the effective contagion graph is a
  *payload-specific* subgraph induced by a host×CVE exploitability structure,
  cleanly separating physical topology from what can actually spread.
- **Novel.** Classical network-epidemic and immunization work runs a homogeneous
  contagion on a fixed graph; SERUM couples the dynamics to a software-vulnerability
  bipartite structure, making *which* subgraph is live a function of the payload.
- **Demonstrate.** Show structure-only centrality mispredicts spread; content
  restricted to `G[c*]` predicts it. **Status: [v1] implemented.**
- **Risk.** "Just SIR on a subgraph." *Mitigation:* the subgraph is unknown and
  must be inferred (N3) — that coupling is the point.

### N2 — Payload-unaware containment as a POMDP with the exploit as hidden state
- **Claim.** A new problem formulation: optimal containment when the adversary's
  exploit is the latent variable and observations are the outbreak itself.
- **Novel.** Cyber-defense RL typically assumes the threat signature is known or
  detected upstream. Treating the *exploit identity* as the belief state, and
  planning under it, is a fresh formulation.
- **Demonstrate.** Full POMDP spec + belief-planning agent beating both
  structure-only and naive "detect-then-act" pipelines. **Status: [v1] core.**

### N3 — Consistency-constrained Bayesian exploit inference from cascade topology
- **Claim.** Online identification of the loose CVE purely from *who falls*,
  using vulnerability-gating as a hard likelihood: each propagation-infected host
  zeroes posterior mass on CVEs it cannot carry.
- **Novel.** Malware *attribution/identification* reframed as Bayesian filtering
  over the inventory from network-observable cascade shape — no payload capture,
  no signatures.
- **Demonstrate.** Identification accuracy & latency vs outbreak size; agent
  performance tracks belief quality. **Status: [v1] implemented; [v2] richer priors.**

### N4 — Identifiability theory of gated inference (the theorem)
- **Claim.** A characterization of *when two exploits are distinguishable* from
  cascade observations (their carrier sets must be "separating" along the
  observed infections), plus a posterior-concentration bound as a function of
  vulnerability-profile diversity — formalized as a **CVE confusability graph**.
- **Novel.** Gives the empirical inference a theoretical backbone: identifiability
  limits are a *structural* property of the inventory, not a modeling artifact.
  (Our tests already exhibit the non-identifiable case: two CVEs every victim
  carries are provably indistinguishable.)
- **Demonstrate.** Theorem + proof; empirical posterior concentration matches the
  bound. **Status: [v2] — the PhD-defining piece.**
- **Risk.** Proof effort. *Mitigation:* start with the exact non-identifiability
  lemma (already observed) and a concentration bound under a diversity assumption.

### N5 — Belief-weighted exposed-vulnerable degree: a payload-conditioned centrality
- **Claim.** A new immunization score = the belief-expected number of
  susceptible, exploitable neighbours a host would infect next; it generalizes
  degree/immunization centrality to the *uncertain-payload* regime and reduces
  to classical degree when the belief is uniform / all-hosts-vulnerable.
- **Novel.** A security-specific centrality that is *belief-conditioned* — a
  measure defined on the posterior over the contagion surface, not the graph alone.
- **Demonstrate.** Ablate against degree/eigenvector; show the reduction in the
  limiting cases. **Status: [v1] implemented.**

### N6 — Information-value action selection: containment-certainty vs availability
- **Claim.** The agent adaptively switches from blunt isolation (high
  uncertainty) to precise patching (low uncertainty) as the belief sharpens,
  formalizing a tradeoff between *containment certainty* and *service
  availability* — a Pareto-optimal treatment of the two objectives.
- **Novel.** Immunization literature optimizes infection alone; SERUM makes
  *collateral disruption* a first-class, belief-driven objective.
- **Demonstrate.** Pareto front (infection vs availability) dominates baselines;
  ablate the switch. **Status: [v1] mechanism; [v2] full Pareto study.**

### N7 — Active sensing / value-of-information probing (dual control for defense)
- **Claim.** Honeypots and targeted scans as *budgeted sensing actions* that
  trade containment budget for faster exploit identification; the agent solves
  an explore(learn the payload)-vs-exploit(contain it) tradeoff.
- **Novel.** Dual control (simultaneous learning and acting) applied to the
  exploit-identification problem — sensing actions chosen by value of information.
- **Demonstrate.** Probing shortens identification latency and improves final
  outcome at fixed budget. **Status: [v2].**

### N8 — Adversarial payload design against the inference (inference-evasion equilibria)
- **Claim.** A Stackelberg/minimax layer where the attacker designs payload +
  seeds to *evade identifiability* — camouflaging behind popular CVEs so the
  belief stays diffuse — not merely to evade detection.
- **Novel.** Prior adversarial-ML/security games target detectors or classifiers;
  here the adversary attacks the *defender's Bayesian inference* itself. Study the
  equilibrium and the price of inference-evasion.
- **Demonstrate.** Best-response attacker degrades naive belief planning; a
  robust (min-max) agent recovers. **Status: [v3].**

### N9 — Learned belief-conditioned GNN meta-policy
- **Claim.** A GNN/RL policy over the belief-augmented graph state (node features
  include posterior-derived exposure) that generalizes across topologies and
  outbreaks and surpasses the analytic planner.
- **Novel.** *Content-aware RL for containment*: the belief over the hidden
  exploit is an explicit policy input — learning to act under payload uncertainty.
- **Demonstrate.** Cross-topology generalization; beats analytic agent; ablate
  the belief features. **Status: [v2].**

### N10 — Language-grounded exploit priors via an LLM tool-use agent (the agentic-AI headline)
- **Claim.** An LLM agent maps CVE text / CVSS vectors (attack vector, attack
  complexity, privileges) into priors over the target CVE and transmissibility,
  and calls SERUM's containment primitives as tools — with the Bayesian tracker
  as verifiable, non-hallucinated memory.
- **Novel.** Bridges *semantic* (natural-language threat intel) and *structural*
  (cascade-topology) inference: language sets the prior, the network sharpens the
  posterior, and a tool-use agent acts — a principled role for an LLM inside a
  rigorous control loop (not a chatbot bolt-on).
- **Demonstrate.** Language priors improve early identification and cold-start
  containment; the tracker prevents belief hallucination. **Status: [v2/v3].**

### Validation contributions (supporting, not "methods")
- **N11 — Empirical grounding.** Reproduce the content-aware advantage on
  NVD/CVE-derived profiles and real SNAP/RocketFuel topologies. **[v2].**
- **N12 — Phase diagram of the advantage.** From the parameter sweep, chart *when*
  content-awareness helps most (as a function of target-CVE prevalence,
  vulnerable-subgraph connectivity, spread rate, budget) — a systematization that
  tells practitioners when the method matters. **[v1.5], data already collected.**

---

## 4. Evaluation protocol

- **Paired design.** Every policy faces the identical outbreak (same graph,
  payload, seeds, and infection coin-flips) — variance-slashing paired trials.
- **Headline ablation (the money plot).** `content-aware (belief)` vs
  `content-aware-oracle (true CVE)` vs `structure-only`. The gap to the oracle
  measures the cost of inference; the gap to structure-only measures the value of
  content-awareness. Both must be significant.
- **Phase diagram.** Sweep topology × `β` × attacker-strategy × budget; report the
  relative infection reduction of content-aware vs the best structure-only
  baseline per cell (N12).
- **Statistics.** Bootstrap CIs + paired significance tests on every headline claim.
- **Stress tests.** Adaptive/adversarial attacker (N8); degraded inference; larger
  networks; real topologies.

---

## 5. Milestones

- **M1 (now → ~1 wk).** Randomize `c*` across trials; add eigenvector/greedy/
  acquaintance-immunization baselines; produce the N12 phase diagram from the
  existing 54-cell sweep; write the formal problem statement.
- **M2 (~1–3 wk).** N4 identifiability theorem (start with the non-identifiability
  lemma + concentration bound); N7 VoI probing; N3 CVSS/text priors; NVD-grounded
  profiles (N11).
- **M3 (~3–6 wk).** N9 learned GNN policy; N2 vs detect-then-act baseline;
  adaptive attacker.
- **M4 (~6–10 wk).** N8 Stackelberg game; N10 LLM tool-use agent; real topologies;
  full experiments; paper draft.

---

## 6. Target venues
- **Security:** AISec (CCS workshop) → RAID, ACSAC → NDSS/USENIX Security (stretch).
- **ML:** NeurIPS/ICLR workshops on agents & GNNs; AAAI; KDD (applied).
- **Networking:** IMC, CoNEXT (measurement/real-topology framing).

## 7. Threats to validity & responsible use
- **Modeling abstraction.** Gated SI is a simplification; mitigate with SIR/SIS,
  real inventories, and sensitivity analyses.
- **Sim-to-real gap.** Grounding in NVD/CVE + real topologies (N11) is the bridge.
- **Responsible use.** SERUM is defensive: it studies faster, lower-collateral
  *containment*. Propagation is modeled abstractly (a probability over an
  exploitability graph); the repo contains no weaponizable attack code.
