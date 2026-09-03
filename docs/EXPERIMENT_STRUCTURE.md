# Structured Experiment Plan for SERUM

## 1. Objective

Evaluate whether a content-aware defender that infers the hidden exploit from observed infections can outperform topology-only containment policies in vulnerability-gated epidemic settings.

## 2. Core research question

Does defending the payload-specific vulnerable subgraph, inferred from the outbreak pattern, reduce infection and preserve availability better than structure-only policies?

## 3. Main hypothesis

In settings where the vulnerable subgraph does not align with topological hubs, a belief-based content-aware defender will achieve lower infection and better availability than topology-only baselines.

## 4. Experimental design

### A. Experimental unit
Each trial is one paired outbreak on a fixed network with a fixed target CVE and fixed seed set.

### B. Paired design
Every policy faces the same outbreak conditions:
- same graph,
- same target CVE,
- same seed hosts,
- same budget and horizon,
- same random stream for infection dynamics.

This reduces variance and makes comparisons more honest.

## 5. Conditions to compare

### Policies
- no-defense
- random
- degree
- betweenness
- eigenvector
- greedy-blocking
- content-aware
- content-aware-oracle

### Variants
- structure-only baselines
- inference-based policy
- oracle policy with full exploit knowledge

## 6. Datasets

### Level 1: Synthetic control
Use synthetic topologies to validate the mechanism under controlled conditions.

Suggested settings:
- BA, WS, ER, RGG
- moderate to high spread rate
- varied prevalence bands
- multiple budgets

### Level 2: NVD-grounded evaluation
Use real CVE metadata from the NVD pipeline to build more realistic vulnerability profiles.

Suggested settings:
- real CVE catalog
- real software-monoculture zones
- real prevalence structure

### Level 3: Measured inventory evaluation
Use a measured host-to-CVE scan plus a topology edge list.

This is the most important step toward making the project feel real-world.

## 7. Factors to vary

### Network structure
- topology type
- degree heterogeneity
- segmentation / community structure

### Vulnerability structure
- prevalence band of target CVE
- homophily / monoculture strength
- overlap between vulnerable zones and hubs

### Defense settings
- budget per step
- horizon
- whether the defender sees noisy observations

## 8. Metrics

Primary metrics:
- infected fraction
- availability preserved
- steps to containment

Secondary metrics:
- win rate vs baseline
- paired improvement
- robustness under detection noise
- sensitivity to prevalence band

## 9. Procedure

1. Sample or load a network.
2. Choose a target CVE and payload strategy.
3. Seed the outbreak.
4. Run every policy on the same outbreak.
5. Record the metrics.
6. Repeat over many paired trials.
7. Report mean outcomes and paired significance tests.

## 10. Statistical analysis

Use:
- paired comparisons,
- bootstrap confidence intervals,
- Wilcoxon signed-rank tests,
- and multiplicity correction when many comparisons are reported.

## 11. Recommended reporting format

For each experiment setting, report:
- the mean infected fraction,
- the mean availability,
- the mean steps to containment,
- the paired improvement over the best structural baseline,
- the number of wins out of N trials,
- and the paired significance p-value.

## 12. Recommended experimental phases

### Phase A — Core claim
Validate the main claim on a small, clean setup.

### Phase B — Robustness
Test sensitivity to:
- prevalence band,
- homophily,
- budget,
- and observation noise.

### Phase C — Real-data grounding
Run the same comparison with NVD-grounded data.

### Phase D — Measured inventory validation
Run the pipeline on a real scan + topology pair.

## 13. Minimal first version

If you want a clean, publishable prototype experiment, start with:
- 1 topology family,
- 1 realistic target-CVE regime,
- 3 policies (degree, betweenness, content-aware),
- 40 paired trials,
- and 3 metrics: infection, availability, containment speed.

That is enough to support a strong first paper-style result.
