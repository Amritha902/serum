# SERUM — Project Manual

*A guide for anyone — a new contributor, a reader, a reviewer, or a faculty
evaluator — to understand what this project is, why it exists, how it works, and
how to run it. No prior familiarity with the codebase assumed.*

---

## 1. What SERUM is, in one minute

**SERUM** (*Semantic Epidemic Response under Unknown Malware*) is a research
testbed that studies a single question:

> When a computer worm is spreading through a network, and you **don't know what
> weakness it's exploiting**, how should a defender with a limited budget stop it?

The core idea: a worm can only infect a machine that runs the specific vulnerable
software it targets. So the worm doesn't travel the whole network — only the
smaller *vulnerable subgraph* of machines that share that weakness. A defender who
knows which weakness is loose can defend exactly those machines. A defender who
only looks at network structure wastes its budget protecting well-connected
machines the worm can't even use.

The twist that makes it a real research problem: **the defender never sees the
attack.** It only sees which machines are infected. SERUM shows that because
spread is vulnerability-gated, the set of infected machines is itself a clue — so
the defender can *infer* the attack online (Bayesian belief), and defend the right
machines, without ever capturing the malware.

**It is strictly defensive.** SERUM is an abstract simulator (a probability over
an exploitability graph); it contains no real or weaponizable malware code.

---

## 2. Why it matters

- **Real incident response is budget-limited.** Defenders can't patch or isolate
  every machine at once. Spending that budget on the wrong machines is a real,
  costly failure mode.
- **Structure-only defense can be nearly useless.** On a real organisational
  network in our experiments, the standard "protect the hubs" approach barely beat
  doing nothing — because the vulnerable machines weren't the hubs. That is exactly
  the situation SERUM is built for.
- **You don't need to capture the malware to defend well.** Inferring the target
  from the outbreak's shape is faster than waiting for a signature to arrive.

---

## 3. The key concepts (glossary)

| Term | Plain meaning |
|---|---|
| **CVE** | A specific software weakness the worm targets (the "attack"). |
| **Vulnerability profile** | The set of weaknesses a given machine has. |
| **Vulnerable subgraph** | The machines that share the worm's target weakness — the only ones it can spread through. |
| **Payload / exploit** | The worm's target weakness; *hidden* from the defender. |
| **Belief** | The defender's probability guess over which weakness is loose, updated as machines fall. |
| **POMDP** | The formal model: decision-making when part of the world (here, the attack) is hidden. |
| **Content-aware agent** | Our defender: infers the attack, then defends the machines that can actually catch it. |
| **Structure-only baseline** | Conventional defenders that only look at connectivity (degree, betweenness, …). |
| **Budget** | How many protective actions (patch / isolate / cut-link) the defender can take per step. |
| **Availability** | Fraction of machines kept running (isolating a machine costs availability; patching doesn't). |

---

## 4. How it works (the pipeline)

```
   Real vulnerability data           Network topology
   (NVD / CVE database)              (synthetic or real SNAP graphs)
            │                                 │
            └──────────────┬──────────────────┘
                           ▼
              Build a network of machines with
              software-monoculture zones  (serum/sim/network.py)
                           │
                           ▼
              A worm targets one hidden weakness c*
              and spreads only through carriers of c*  (serum/sim/payload.py,
                           │                            serum/sim/environment.py)
          ┌────────────────┼────────────────────────────┐
          ▼                ▼                             ▼
  Structure-only     Content-aware agent           Oracle (knows c*)
  baselines          (infers c* via Bayesian        = upper bound
  (the competition)   belief, then defends)         (serum/agents/…)
          └────────────────┼────────────────────────────┘
                           ▼
              Paired evaluation: every defender faces the
              identical outbreak  (serum/experiments/harness.py)
                           │
                           ▼
              Metrics + statistics → results/*.json → paper
```

---

## 5. Repository map (where everything lives)

```
serum/
├── sim/            the world: networks, the worm, the containment game
│   ├── network.py      build machines with mixed software profiles
│   ├── payload.py      the attacker's exploit (target weakness + spread rate)
│   └── environment.py  the POMDP: patch / isolate / segment under a budget
├── inference/      figuring out the hidden attack
│   ├── belief.py       Bayesian belief over the unknown weakness
│   ├── identifiability.py   the exact "when is it identifiable" theorem
│   ├── divergence.py   metric for WHEN content-awareness helps
│   ├── diversity.py    canary planning to engineer identifiability
│   ├── multi_exploit.py     polymorphic (multi-weakness) worms
│   └── multiplicity.py Holm-Bonferroni statistical correction
├── agents/         the defenders
│   ├── content_aware.py     the main agent (ours)
│   ├── robust.py            poison-resistant agent (audits + hedges)
│   ├── learned.py           machine-learned policy
│   └── committee/stopping/probing/threat_intel.py   variants
├── baselines/      the conventional defenders SERUM competes against
├── attack/         adversaries (adversarial payload, deception, adaptive)
├── data/           real-data pipeline (NVD fetch, clean, profiles, topologies)
├── scenarios/      applications (IoT / Mirai botnet)
└── experiments/    the paired-trial harness that drives every experiment

scripts/   ~27 runnable experiments, one per result (each writes results/*.json)
tests/     128 tests, incl. test_paper_claims.py (every paper number is checked)
docs/      the writing: this manual, RESEARCH.md, THEORY.md, LITERATURE_REVIEW.md,
           CONTRIBUTIONS.md (the 4 core claims), DEVLOG.md, BACKLOG.md
paper/     serum.tex — the full research paper draft (+ refs.bib)
results/   the JSON/PNG artifacts every table and figure is generated from
```

---

## 6. The headline results (what we found)

| Setting | Best conventional defense | **SERUM (ours)** | Significance |
|---|---|---|---|
| Synthetic, real CVEs (40 trials) | 3.4% infected | **1.8% infected**, higher availability | Pareto-dominant |
| **Real org network** (email-Eu-core) | 17.6% infected | **11.7% infected** (−28.4%) | p = 1.7×10⁻⁷ |
| Real NVD data (60 trials) | 1.5% infected | **0.9% infected** (−18.6%) | p = 1.1×10⁻⁵ |

Plus: the identifiability theorem validated **116/116 = 100%**; robustness to
evasion and poisoning (holds up to 6% fleet poisoning even under a best-response
attacker); and all 11 headline comparisons survive multiple-comparison correction.

**The four core claims are written up in [`CONTRIBUTIONS.md`](CONTRIBUTIONS.md).**

---

## 7. How to run it

```bash
# one-time setup
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# the headline experiment (prints a table, saves a figure)
python scripts/run_experiment.py --trials 30

# sanity-check the epidemic regime
python scripts/diagnose.py

# regenerate EVERY results/ artifact from scratch
python scripts/reproduce_all.py            # add --fast to skip slow ones

# run the test suite (spread is gated; belief never excludes the truth; every
# paper number matches its results file; ...)
pytest -q
```

Everything runs on `numpy` + `networkx` — no GPU, no heavy dependencies.

**Validating on a real host-level inventory (the L1 experiment).** If you have a
real vulnerability scan (a table of measured `host, cve` findings) and a topology
edge list, you can run the full evaluation on *measured* data in one command:

```bash
python scripts/validate_real_inventory.py --scan scan.csv --edges edges.csv
# (no arguments -> a self-test on a synthetic fixture, proving the pipeline runs)
```

The host↔CVE mapping is taken verbatim from the scan (not modeled). This is the
single most valuable validation the project still needs; it is gated only on
access to such (typically proprietary) scan data — see limitation L1.

---

## 8. What's honest about it (the caveats we state up front)

Good research states its limits. SERUM's main ones:

- **L1 (the big one).** Content-awareness helps when the vulnerable machines are
  *not* the network hubs. We prove this holds on real vulnerability data and two
  real topologies, but **not yet on a real host-level enterprise network** with
  measured per-machine vulnerabilities — that data is proprietary. This is the
  single most valuable next validation.
- **L2.** The online inference is a *refinement*, not the sole driver of the win —
  defending the observation-consistent subgraph already over-covers the true
  victims.
- **The model is abstract.** Propagation is a probability over an exploitability
  graph; there is no packet-level malware emulation.

The full list is in the paper's Limitations section (L1–L7), and the honest
prior-art positioning is in [`LITERATURE_REVIEW.md`](LITERATURE_REVIEW.md).

---

## 9. Where to go next (by role)

- **Just want the idea?** Read §1–§2 here, then the plain-language explainer.
- **Evaluating the science?** Read [`CONTRIBUTIONS.md`](CONTRIBUTIONS.md) (4 core
  claims + honest scope), then [`THEORY.md`](THEORY.md) for the theorem, then the
  paper.
- **Contributing code?** Read §5 (repo map), run §7, and see
  [`BACKLOG.md`](BACKLOG.md) for open work.
- **Checking rigor?** `pytest -q`, then `python scripts/reproduce_all.py`, then
  read [`DEVLOG.md`](DEVLOG.md) for the full build-and-grill history.
