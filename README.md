# Argus — Content-Aware Agentic Containment of Malware Propagation

> **Thesis.** A defender that reasons about *what* is spreading — the payload's
> target vulnerability — contains a network worm far more efficiently than one
> that only sees network *structure*, because malware can only traverse hosts
> whose software is actually exploitable. Argus makes that reasoning work even
> when the payload is **never observed**, by inferring it from the shape of the
> outbreak.

Argus is a research testbed at the intersection of **network science**,
**cyber-defense**, and **agentic AI**. It models a worm spreading across a
heterogeneous host network and pits *structure-only* containment heuristics
against a *content-aware* agent that maintains a Bayesian belief over the
attacker's exploit and allocates its defensive budget accordingly.

---

## The core result

Same network, same worm, same budget — six defenders. Lower infection is
better; higher availability is better; contained-by-step is faster.

| Policy | Infected | Availability | Contained @ step |
|---|---:|---:|---:|
| no-defense | 35.9% | 100.0% | 13.8 |
| random isolation | 25.8% | 87.4% | 12.7 |
| degree immunization *(structure-only)* | 3.7% | 94.9% | 5.1 |
| betweenness immunization *(structure-only)* | 3.6% | 94.9% | 5.1 |
| **content-aware agent *(ours, partial-obs)*** | **1.7%** | **98.6%** | **3.1** |
| content-aware oracle *(upper bound)* | 1.1% | 100.0% | 2.2 |

*30 paired outbreaks, 500-host Barabási–Albert network, stealth payload. See
`results/summary.json` and `results/infection_curves.png`.*

The content-aware agent **halves the infected fraction** relative to the best
structure-only baseline, **keeps more of the network online** (it patches
precisely instead of bluntly isolating), and **contains faster** — while
*inferring* the payload rather than being told it. It sits close to the
full-observability oracle, so the inference leaves little on the table.

---

## Why this is a non-trivial problem

The physical topology is *not* the propagation graph. A payload targeting CVE
`c` can only move through the **vulnerable subgraph** induced by hosts that
carry `c`. A high-degree hub is irrelevant if it cannot run the exploit —
budget spent immunizing it is wasted. Structure-only defenders are blind to
this; the content-aware agent defends the subgraph that can actually spread.

The twist that makes it PhD-shaped: **the defender never sees the payload.**
It observes only who is infected. Because spread is vulnerability-gated, every
host infected *by propagation* is a hard constraint on which CVE is loose — so
Argus runs Bayesian inference over the exploit (a POMDP) and acts under that
belief, hedging early and sharpening as the outbreak reveals its target.

---

## Architecture

```
argus/
├── sim/           heterogeneous networks + vulnerability-gated SI spread
│   ├── network.py      hosts with heavy-tailed CVE profiles; vulnerable subgraphs
│   ├── payload.py      the attacker's exploit (target CVE + transmissibility)
│   └── environment.py  the containment POMDP: budgeted patch / isolate / segment
├── inference/     Bayesian belief over the unobserved payload CVE
│   └── belief.py       consistency-constrained posterior; MAP, entropy, support
├── baselines/     structure-only interveners (random, degree, betweenness)
├── agents/        content-aware agent (belief-weighted exposed-vulnerable degree)
└── experiments/   paired-trial harness, metrics, comparison
```

Everything runs on `numpy` + `networkx` — no GPU, no heavy deps.

---

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# headline experiment (table + saved figure)
python scripts/run_experiment.py --trials 30

# sanity-check the epidemic regime
python scripts/diagnose.py

# overnight robustness sweep (topologies × spread rates × strategies × budgets)
python scripts/sweep.py --trials 40      # appends to results/sweep.jsonl

# tests (spread is vulnerability-gated; belief never excludes the true CVE; ...)
pytest -q
```

---

## Roadmap

The current agent is a principled but *analytic* planner. The research program
layers learning and adversaries on top of this testbed:

- **Learned policy.** Replace the hand-scored planner with a GNN policy over the
  belief-augmented state (the simulator already exposes a clean step interface).
- **Richer payloads.** Multi-CVE, polymorphic, and dwell-time worms — the belief
  becomes a distribution over exploit *sets*.
- **Adversarial co-design.** A Stackelberg game: the attacker picks payload and
  seeds to defeat the inference; study the equilibrium.
- **Real inventories.** Drive vulnerability profiles from NVD/CVE data and real
  topologies (SNAP AS graphs, RocketFuel).
- **LLM tool-use agent.** An agent that reads structured threat intel and calls
  the containment primitives as tools, with the Bayesian tracker as memory.

---

## Responsible use

Argus is a **defensive** research tool: it studies how to *contain* outbreaks
faster and with less collateral disruption. The simulator models propagation
abstractly (a probability over an exploitability graph) and contains no
weaponizable attack code.

## License

MIT — see [LICENSE](LICENSE).
