# SERUM — Related Work & Honest Novelty Verdicts

This document is the result of a systematic prior-art audit (six parallel
literature surveys, all citations verified against arXiv / publisher pages). Its
purpose is to keep SERUM honest: to state plainly what is **not** novel, what is
**genuinely** novel, and exactly which papers we must cite and differentiate
from. Overclaiming sinks papers; this is our defense.

## TL;DR — where SERUM actually stands

- **The propagation model (vuln-gated spread) is NOT novel.** It is a special
  case of multitype bond percolation and the explicit premise of software-
  diversity worm models. We cite these and claim no novelty for the mechanism.
- **The identifiability theory is INCREMENTAL.** Cascade-mixture identifiability
  already exists (Hoffmann et al., ICML 2020). Our delta is specializing it to
  *observable* vulnerability profiles.
- **GNN+RL immunization is ESTABLISHED** (RLGN, FINDER). Not a contribution by
  itself.
- **SERUM's defensible, genuinely-underclaimed core:** *online Bayesian inference
  of the unobserved exploit/CVE from the vulnerability-gated cascade shape,
  coupled to budgeted containment, grounded in real CVE data.* The single closest
  system (CyGym, 2025) has vuln-gated spread + budgeted defense but uses a
  **static prior** over zero-days — it does **not** update a belief over the
  attacker's exploit from the observed spread. That online-inference ingredient
  is our lane.

---

## The nearest neighbor — cite prominently, differentiate sharply

**CyGym: A Simulation-Based Game-Theoretic Analysis Framework for Cybersecurity.**
Lanier & Vorobeychik, arXiv:2506.21688 (2025).
- Has: (i) lateral movement **gated on host vulnerabilities**, (iii) **cost/
  budget-limited** defense.
- Lacks: (ii) **online inference** of the attacker's capability from the spread
  — it assumes a *fixed common prior over possible zero-days*.
- **SERUM's difference:** we make (ii) the centerpiece — a belief over the exploit
  that is *updated from the observed infected set* via vulnerability-consistency,
  and we act under that belief. State this distinction explicitly.

---

## Theme 1 — Vulnerability-gated propagation (our N1): INCREMENTAL

| Prior work | Cite | Why close | SERUM differs |
|---|---|---|---|
| Multitype bond percolation, Allard et al., Phys. Rev. E 79 036113 (2009), arXiv:0811.2349 | ✔ | Edge occupation gated by node *type* → attribute-induced subgraph is a special case | We instantiate types as real CVEs; the gate is *observable* |
| Software-diversity worm models (Zhou & Wu; arXiv:2007.08469) | ✔ | Worm crosses a link only if neighbor runs vulnerable software — identical mechanism | We add defender-side exploit inference + containment |
| AAWP worm model, Chen, Gao, Kwiat, INFOCOM 2003; Staniford–Paxson–Weaver, USENIX Sec 2002 | ✔ | Classic worm epidemics gate on a vulnerable population | We use a per-payload *subgraph*, not a scalar population |

**Verdict:** do not claim the model as new. Frame N1 as a realistic instantiation.

## Theme 2 — Inferring *which* exploit from cascade shape (our N2/N3): NOVEL but must be framed

| Prior work | Cite | Why close | SERUM differs |
|---|---|---|---|
| SCENARIOID, Harrison et al., **KDD 2023** | ✔ 🔴 | Infers a latent generating *scenario* from cascade **shape** | Their latent = intervention regime, offline & feature-based; ours = exploit identity, **online belief/POMDP**, vuln-gated |
| Active hypothesis testing, Naghshvar & Javidi, arXiv:1211.2291 | ✔ | The POMDP/belief template we instantiate | Our novelty is the cascade-shape + vuln-gating observation model, not the belief machinery |
| Source detection: Shah & Zaman (SIGMETRICS 2010); Pinto–Thiran–Vetterli (PRL 2012) | ✔ | "Infer a hidden cause from who's infected" | They infer *where it started*; we infer *what exploit* |
| NetInf / NetRate, Gomez-Rodriguez et al. (KDD 2010 / ICML 2011) | ✔ | Infer diffusion structure from cascades | They infer edges/rates (graph unknown); we invert it (graph known, categorical payload unknown) |
| Correlated Cascades, Zarezade et al., AAAI 2017 | ✔ | Multiple competing contagions | They fit *known* cascades' interaction; we *identify which* is present |
| Cyber POMDPs: Miehling–Rasouli–Teneketzis (2018); Active deception iPOMDP (arXiv:2007.09512) | ✔ | Belief-state cyber defenders | Their belief = compromise state / intent; ours = the exploit/CVE |

**Verdict:** genuinely novel *cell* (online exploit-identity inference from vuln-
gated cascades), but only defensible if framed against SCENARIOID + active
hypothesis testing. Read SCENARIOID and the cyber-POMDP line in full before
finalizing.

## Theme 3 — Identifiability (our N4): INCREMENTAL, salvageable if narrow

| Prior work | Cite | Why close |
|---|---|---|
| Learning Mixtures of Graphs from Epidemic Cascades, Hoffmann, Basu, Goel, Caramanis, **ICML 2020**, arXiv:1906.06057 | ✔ 🔴 | Same theorem shape: "edge-separated" necessary-&-sufficient identifiability of which graph a cascade came from |
| Finding the Graph of Epidemic Cascades, Netrapalli & Sanghavi, SIGMETRICS 2012 | ✔ | Separation-style recovery conditions |
| On Parameter Identifiability in Network-Based Epidemic Models, Kiss & Simon, Bull. Math. Biol. 2023, arXiv:2208.07543 | ✔ | Structural vs practical identifiability backbone (corrected: earlier draft misattributed this as "Sridhar et al.") |

**Verdict:** our delta = a separating condition stated over **CVE profiles** (an
*observable, checkable combinatorial* condition), coupled to N1's induced
subgraph. Cite Hoffmann et al. explicitly and articulate the delta, or a reviewer
calls it a re-derivation.

## Theme 4 — Multi-objective containment (infection vs availability) (our N6): INCREMENTAL

Emmerich et al. (arXiv:2010.06488, Pareto cost-vs-threshold immunization);
Matamalas–Arenas–Gómez (Sci. Adv. 2018, containment preserving connectivity);
Van Mieghem et al. (PRE 2011, spectral link removal); Lorch et al. (arXiv:1810.13043,
stochastic optimal control of epidemics). **Differentiator:** put *infected
fraction* and *service availability* as **co-equal Pareto objectives**, not
connectivity-as-constraint or cost-as-node-count.

## Theme 5 — Active sensing / value of information (our N7): INCREMENTAL

CELF, Leskovec et al. (KDD 2007, static baseline); Spinelli–Celis–Thiran (WWW
2017, online adaptive sensor placement — closest); Zejnilović et al. (GlobalSIP
2015, sequential observer selection as DP); Krause & Guestrin (UAI 2005, VoI);
ρ-POMDP, Araya-López et al. (NeurIPS 2010); Feldbaum dual control (1960-61).
**Differentiator:** explicit *dual-control* framing (probe-to-identify-the-exploit
vs act-to-contain), which the source-localization sensing work does not adopt.

## Theme 6 — Adversarial payload vs the defender's inference (our N8): NOVEL (underexplored)

Fanti et al., rumor-source obfuscation / "Spy vs Spy" (SIGMETRICS 2015,
arXiv:1412.8439); Shokri, privacy games against an inference adversary (PETS
2015, arXiv:1402.3426); Biggio et al., evasion attacks (ECML-PKDD 2013, detector-
evasion contrast). **The intersection — a Stackelberg game on a diffusion process
where the follower defeats the leader's *inference/estimation* — appears
unoccupied.** Position as bridging Shokri-style estimation-evasion games with
Fanti-style diffusion source-inference.

## Theme 7 — GNN + RL immunization (our N9): ALREADY ESTABLISHED

RLGN, Meirom et al. (ICML 2021, arXiv:2010.05313); FINDER, Fan et al. (Nature MI
2020); vaccine-prioritization GNN+DRL, Ling et al. (2024, arXiv:2305.05163).
**Not a contribution alone.** Only defensible with a differentiator: learning
*under exploit-uncertainty* / against an *adversarially-obfuscated* diffusion.

## Theme 8 — LLM agents for security (our N10): MOSTLY ESTABLISHED

CTIBench (NeurIPS 2024, arXiv:2406.07599); "LLMs are Autonomous Cyber Defenders"
in CAGE-4 (IEEE CAI 2025, arXiv:2505.04843); CVSS-BERT (arXiv:2111.08510); LLM-as-
prior for RL (ICLR 2025, arXiv:2410.07927). **The one open slice:** an LLM that
reads CVE/CVSS *text* to emit a **prior belief over the attacker's exploited
vulnerability** feeding the containment planner — no exact prior match found.
Frame modestly.

## Autonomous-defense gyms (baselines to compare against)

CybORG (arXiv:2108.09118); CAGE Challenge 4 (AAAI 2025); CyberBattleSim
(Microsoft 2021); Yawning Titan; FARLAND. None centers the defender on *inferring
an unobserved attacker capability from the spread*.

---

## The one-paragraph honest pitch (use this in the intro)

> Malware propagates only across hosts exploitable by its payload, so the
> effective contagion graph is a payload-specific subgraph of the network
> (a known idea: multitype percolation; software-diversity worms). We study the
> *defender* who does **not** observe the payload and must **infer which exploit
> is spreading, online, from the vulnerability-consistency structure of the
> infected set** — a belief-state we then act on under a containment budget.
> Unlike CyGym's static zero-day prior, the belief is updated from the observed
> spread; unlike SCENARIOID's offline scenario classification, inference is a
> sequential POMDP tied to a checkable identifiability condition on CVE profiles;
> and we ground the whole pipeline in real NVD data. The contribution is the
> *coupling*: because the induced subgraph is fixed by observable node
> attributes, exploit-identifiability becomes a combinatorial condition on
> vulnerability profiles, and content-aware containment provably beats structure-
> only immunization on the axes where the exploit is stealthy.

## Papers to READ IN FULL before submission (highest collision risk)
1. **CyGym** (arXiv:2506.21688) — nearest system.
2. **SCENARIOID** (KDD 2023) — nearest inference-from-shape.
3. **Hoffmann et al.** (ICML 2020) — nearest identifiability theorem.
