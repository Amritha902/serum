# SERUM — Repository Draft

## Project overview

SERUM is a research testbed for content-aware containment of malware propagation under an unobserved payload. The repository studies a defender that does not see the attacker’s exploit directly, but can infer it from the pattern of infections and then allocate containment actions more precisely than structure-only policies.

The central idea is simple and defensible: malware spreads only across hosts that are actually exploitable by its target vulnerability, so the effective contagion graph is a payload-specific subgraph of the network. A defender that reasons about that exploit rather than only about topology can defend the right hosts and reduce collateral disruption.

---

## What the repository contains

The repository is organized around a complete research pipeline:

- Simulation and environment logic for vulnerability-gated spread
- Inference and belief tracking for the hidden exploit
- Policy implementations for content-aware and structural defenders
- Experiment scripts for synthetic and real-data evaluation
- Results, figures, and a paper draft
- Tests and documentation for reproducibility and review

In short, this is not just a demo script. It is a full research prototype with a modular codebase, experiments, evaluation infrastructure, and documentation.

---

## Core problem

The project models a malware outbreak in a network where:

- each host carries a vulnerability profile,
- the attacker targets an unknown CVE,
- the worm spreads only through hosts that are vulnerable to that exploit,
- and the defender observes the infected set but not the exploit itself.

This makes the problem a partially observed decision problem: the defender must infer the hidden payload from observed infections and then act under uncertainty.

---

## Main approach

SERUM combines three ingredients:

1. A vulnerability-gated epidemic model
   - the effective spread graph depends on the exploit and the host vulnerability inventory.

2. A belief over the hidden exploit
   - the defender maintains a posterior over candidate CVEs using infection-consistency constraints.

3. A content-aware containment policy
   - the defender prioritizes hosts that are both likely to be exposed and actually exploitable by the inferred payload.

This produces a policy that is more targeted than pure topology-based immunization.

---

## Why this is interesting

Traditional network-defense strategies often focus on topology alone: remove high-degree nodes, cut central links, or isolate likely hubs. That can be wasteful when the worm can only use a subset of hosts that actually carry the relevant vulnerability.

SERUM’s contribution is that it shifts the defender’s perspective from:

- “who is central in the graph?”

to

- “which hosts are actually relevant to the exploit that is spreading?”

That shift is the core scientific value of the repository.

---

## Evidence in the repository

The repository contains evidence supporting the claim that content-aware defense can outperform structure-only methods in the studied regime.

### Synthetic experiment

The main synthetic result in the repository shows that the content-aware policy reduces infection compared with structural baselines such as degree, betweenness, and eigenvector immunization.

The headline numbers reported in the repository are:

- content-aware infection: about 1.75% versus about 3.39% for the strongest structural baseline in the main synthetic result,
- higher availability and faster containment,
- and a statistically significant paired improvement in the reported experiment.

### Real-data grounding

The repository also includes a real-data pipeline using NVD/CVE information and real network structure. The reported real-data results show the content-aware policy outperforming the best fixed structural baseline and an oracle-after-delay baseline.

### Additional robustness analysis

The repository includes:

- ablations,
- robustness sweeps,
- prevalence-curve analysis,
- and a multiplicity analysis.

These strengthen the case that the effect is not an artifact of a single setting.

---

## Sharper claims to make

The strongest framing for the repository is not that it is a general autonomous cyber-defense system. A more precise and defensible position is:

> In vulnerability-gated epidemic settings, a defender that updates a belief over the attacker’s exploit and acts on the resulting vulnerable subgraph can outperform topology-only containment policies, especially when vulnerable zones do not align with network hubs.

That is a strong, focused claim that fits the repository’s evidence.

### The best three claims are:

1. Online exploit inference from infection patterns is possible under vulnerability-gated spread.
2. Content-aware containment can be more targeted than topology-only immunization.
3. The advantage is largest in segmented or monoculture-like environments where the vulnerable subgraph diverges from topological centrality.

---

## What the repository does not yet justify as a headline claim

The repository should not overstate the scope of its results. The current evidence does not fully justify claims such as:

- that the system is a complete real-world cyber-defense solution,
- that it beats all relevant prior systems in production settings,
- or that the LLM/agentic angle is the primary contribution.

Those are better treated as extensions or future work rather than central claims.

---

## Limitations to acknowledge honestly

The current repository is promising, but it remains a research prototype. The main limitations are:

- the threat model is simplified,
- the experiments are still simulation- and model-driven to a large extent,
- the “real data” is partially grounded rather than fully measured from real enterprise inventories,
- and the strongest comparisons to close prior systems still need to be tightened.

Those limitations should be acknowledged clearly in any paper or presentation.

---

## Suggested one-paragraph summary

SERUM studies a malware-containment problem in which the attacker’s exploit is hidden and the defender must infer it from the evolving infection pattern. The project models propagation as vulnerability-gated, maintains a posterior over candidate exploits, and uses that belief to allocate containment resources more precisely than structure-only policies. Across synthetic and NVD-grounded experiments, the content-aware defender reduces infection and preserves availability better than strong structural baselines, especially in settings where vulnerable software zones are misaligned with network hubs. The project is best framed as a research testbed and decision-theoretic study of content-aware epidemic containment under hidden payload uncertainty.

---

## Bottom line

The repository is already a meaningful research artifact. Its strength is not that it solves every cybersecurity problem, but that it studies a clear and technically interesting question: can a defender infer the hidden exploit from observed spread and use that belief to contain outbreaks more effectively than topology-only methods?

That is a real contribution, and it is strong enough to support a sharper, more disciplined story.
