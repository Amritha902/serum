# SERUM — Content-Aware Agentic Containment of Malware Propagation

*SERUM — **S**emantic **E**pidemic **R**esponse under **U**nknown **M**alware.*
Like an immune system that reads a pathogen's signature before it responds,
SERUM identifies *what* is spreading and defends only the hosts that can
actually catch it.

> **Thesis.** A defender that reasons about *what* is spreading — the payload's
> target vulnerability — contains a network worm far more efficiently than one
> that only sees network *structure*, because malware can only traverse hosts
> whose software is actually exploitable. SERUM makes that reasoning work even
> when the payload is **never observed**, by inferring it from the shape of the
> outbreak.

SERUM is a research testbed at the intersection of **network science**,
**cyber-defense**, and **agentic AI**. It models a worm spreading across a
heterogeneous host network and pits *structure-only* containment heuristics
against a *content-aware* agent that maintains a Bayesian belief over the
attacker's exploit and allocates its defensive budget accordingly.

---

## The core result

Nine defenders, same network, same worm, same budget, **randomized attack
target** (payload CVE drawn per trial). Lower infection is better; higher
availability is better; contained-by-step is faster.

| Policy | Infected | Availability | Contained @ step |
|---|---:|---:|---:|
| no-defense | 36.6% | 100.0% | 14.2 |
| random isolation | 23.0% | 88.4% | 11.6 |
| acquaintance immunization *(structural)* | 22.6% | 88.6% | 11.4 |
| degree immunization *(structural)* | 3.4% | 95.5% | 4.5 |
| eigenvector immunization *(structural)* | 4.5% | 94.4% | 5.6 |
| betweenness immunization *(structural)* | 3.4% | 95.5% | 4.5 |
| greedy influence-blocking *(structural)* | 12.3% | 89.5% | 10.4 |
| **content-aware agent *(ours, partial-obs)*** | **1.8%** | **98.5%** | **3.0** |
| content-aware oracle *(upper bound)* | 1.1% | 100.0% | 2.0 |

*40 paired outbreaks, 500-host Barabási–Albert network, β=0.35, target CVE
sampled per trial. See `results/summary.json` and `results/infection_curves.png`.*

**What holds up under rigorous, paired, randomized-target evaluation:**

1. **Pareto dominance (the robust win).** The content-aware agent is at least as
   good on infection as *every* structural baseline and **strictly better on
   availability *and* containment speed** — because it patches precisely instead
   of bluntly isolating. No baseline dominates it on any axis.
2. **Significant infection reduction vs the best deployable baseline.** Paired
   vs betweenness (the strongest fixed structural policy): **−1.65 pts, 95% CI
   [0.50, 3.13], Wilcoxon p = 0.025**.
3. **The advantage scales with outbreak severity** (`results/prevalence_curve.png`).
   Across exploit-prevalence bands it is significant in **4 / 5** bands and grows
   with how bad the outbreak is — up to **−3.7 pts (2.4× lower infection),
   p < 0.001** for the most severe outbreaks. It never significantly loses.

**Honest scope.** Against an *oracle ensemble* that cherry-picks the best
structural heuristic per outbreak, the infection edge is not significant
(p ≈ 0.84) — no single deployable defender is that oracle, but we report it in
full. All of the above is achieved while the agent **infers** the payload rather
than being told it, landing close to the full-observability oracle.

See [`docs/RESEARCH.md`](docs/RESEARCH.md) for the full design and the 12-point
novelty register, [`docs/LITERATURE_REVIEW.md`](docs/LITERATURE_REVIEW.md) for a comprehensive,
source-verified survey of the field, [`docs/RELATED_WORK.md`](docs/RELATED_WORK.md)
for the prior-art audit and honest novelty verdicts, [`docs/THEORY.md`](docs/THEORY.md)
for the exploit-identifiability theorem (proofs + 100% empirical validation), and
[`paper/serum.tex`](paper/serum.tex) for the paper draft.

## Exploit-identifiability theory

Because the propagation subgraph is fixed by *observable* node attributes, the
unobserved exploit is identifiable from a saturating outbreak **iff the
intersection of the infected hosts' CVE profiles is a singleton** — a condition
a defender can check in advance from its asset inventory. `scripts/identifiability.py`
validates that the Bayesian belief recovers the true CVE exactly when the theorem
predicts (**116/116 = 100%**); ~54% of real CVEs are identifiable this way.

## Real-data grounding (NVD/CVE)

SERUM is not confined to synthetic vulnerabilities. A proper ingestion pipeline
pulls real CVEs from the **NVD 2.0 API**, cleans and validates them across CVSS
generations, and derives host vulnerability profiles from real CPE products and
CVSS scores:

```bash
python scripts/ingest_nvd.py --limit 6000        # fetch recent CVEs -> data/clean/cves.csv
python scripts/run_experiment.py --trials 40 --real   # run on real-data networks
```

- `serum/data/nvd.py` — cached, rate-limited, retrying NVD client (date-windowed).
- `serum/data/clean.py` — parse/validate/dedup ragged NVD JSON into typed records.
- `serum/data/profiles.py` — real CPE-product co-deployment → correlated host
  vulnerabilities; per-CVE transmissibility from CVSS.

Software is assigned with **segment-correlated monoculture**: the graph is carved
into connected zones (subnets/VLANs) that share a software image (`homophily`
controls the strength), so a CVE induces a connected vulnerable subgraph — as
real worms actually spread. Crucially, that vulnerable *zone* need not coincide
with the topological hubs, which is where content-awareness pays off.

**Real-data result (60 paired outbreaks, real modern CVEs, `results/real/`):**

| Policy | Infected | Availability | Contained @ step |
|---|---:|---:|---:|
| no-defense | 14.0% | 100.0% | 10.5 |
| degree immunization *(best structural)* | 1.5% | 96.9% | 3.1 |
| oracle-after-delay *(threat intel at t=5)* | 1.4% | 97.3% | 2.9 |
| **content-aware** | **0.9%** | **98.3%** | **2.0** |

- vs the best fixed baseline: **−18.6% infection, Wilcoxon p = 1.1×10⁻⁵**.
- vs the per-trial **ensemble oracle**: **−8.4%, p = 0.002** — on real data the
  content-aware agent beats even the oracle that cherry-picks the best structural
  heuristic per outbreak (which it *cannot* do on synthetic data), because real
  software zones genuinely diverge from topological centrality.
- vs the **oracle-after-delay** (the realistic competitor that receives the true
  signature at t=5): content-aware wins — **inferring the exploit online beats
  waiting for threat intel to arrive.**

The exploit belief uses a **soft likelihood** robust to detection noise: a single
false-positive infection cannot wrongly exclude the true CVE (the failure mode of
hard consistency filtering) — see `tests/test_sim.py`.

### Flagship: a real network with real community structure

Beyond synthetic graphs, SERUM runs on the SNAP **email-Eu-core** network (1004
hosts, 42 real organisational **departments**), using the departments directly as
software zones — a real community structure, not a synthetic partition. Loader:
`serum/data/topology.py` (downloads + caches from SNAP; `--topology email`).

Real topology + real departments + real NVD CVEs (40 paired outbreaks, budget 8):

| Policy | Infected | Availability |
|---|---:|---:|
| no-defense | 20.1% | 100.0% |
| degree immunization *(structural)* | 18.8% | 92.2% |
| betweenness *(best structural)* | 17.6% | 92.5% |
| oracle-after-delay (t=5) | 18.1% | 96.2% |
| **content-aware (ours)** | **11.7%** | **97.5%** |
| content-aware oracle (bound) | 9.1% | 100.0% |

On a real org network, **structure-only immunization barely helps** (17.6% vs
no-defense 20.1%) because the vulnerable *department-zones do not align with the
topological hubs* — exactly the regime SERUM's thesis predicts. Content-aware
cuts infection to **11.7% — −28.4% vs the best fixed baseline, Wilcoxon
p = 1.7×10⁻⁷** — and beats the per-trial ensemble oracle (p = 1.9×10⁻⁷).
Data: `results/real/email_topo.json`.

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
SERUM runs Bayesian inference over the exploit (a POMDP) and acts under that
belief, hedging early and sharpening as the outbreak reveals its target.

---

## Architecture

```
serum/
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

SERUM is a **defensive** research tool: it studies how to *contain* outbreaks
faster and with less collateral disruption. The simulator models propagation
abstractly (a probability over an exploitability graph) and contains no
weaponizable attack code.

## License

MIT — see [LICENSE](LICENSE).
