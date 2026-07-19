# SERUM — Literature Review

A comprehensive, **source-verified** survey of the fields SERUM touches, written
to (a) position the work honestly, (b) supply the paper's related-work section,
and (c) preempt reviewer objections. Every citation below was checked against an
arXiv abstract page and/or the publisher/proceedings page during a multi-agent
literature audit; items that could not be fully verified are flagged. Where the
project's earlier notes carried an incorrect attribution, the correction is
called out inline (search "CORRECTION").

**How to read the "→ SERUM" lines.** Each entry ends with one line stating
whether the work is an *antecedent* SERUM builds on, a *baseline* SERUM compares
against, a *differentiator* SERUM must distinguish itself from, or a *collision*
(a paper close enough that reviewers will pattern-match — cite prominently and
state the delta in the same breath).

**The one-paragraph thesis of this review.** SERUM's individual ingredients are
each well-precedented: the propagation model is heterogeneous multitype
percolation; its containment baselines are classical network immunization; the
POMDP/active-hypothesis-testing machinery is standard; GNN-RL immunization and
LLM-as-prior are established. SERUM's defensible contribution is the *specific
combination that no prior work occupies*: **online Bayesian inference of the
unobserved exploit from a vulnerability-gated cascade, with an exact
identifiability condition on observable node attributes, driving budgeted
content-aware containment, grounded in real NVD/CVE data.** The closest system,
CyGym (2025), has vulnerability-gated spread and a cost model but uses a *static*
prior over zero-days with *no* online belief update — the precise gap SERUM
fills.

---

## Theme 1 — Network epidemic theory & malware/worm propagation

### 1a. Epidemic spreading on networks (the mathematical substrate)
- **Pastor-Satorras & Vespignani, "Epidemic Spreading in Scale-Free Networks," PRL 86:3200 (2001).** Degree-based mean-field SIS; the epidemic threshold vanishes as ⟨k²⟩ diverges. → *antecedent*: the relevant threshold for SERUM is that of the *vulnerable subgraph*, not the full graph.
- **Newman, "Spread of epidemic disease on networks," PRE 66:016128 (2002); arXiv:cond-mat/0205009.** Maps SIR to bond percolation with possibly non-uniform occupation probabilities. → *foundational antecedent*: vulnerability-gating is a 0/1 occupation probability, a case this framework already admits.
- **Pastor-Satorras, Castellano, Van Mieghem & Vespignani, "Epidemic processes in complex networks," Rev. Mod. Phys. 87:925 (2015); arXiv:1408.2701.** The authoritative modern review. → *umbrella citation* situating SERUM's model in mature theory.

### 1b. Heterogeneous / multitype / multi-strain models (type gates transmission)
- **Allard, Noël, Dubé & Pourbohloul, "Heterogeneous bond percolation on multitype networks…," PRE 79:036113 (2009); arXiv:0811.2349.** Type-dependent edge-occupation probabilities; spectral phase-transition criterion on the type-level next-generation matrix. → **the mathematical parent that subsumes SERUM's mechanism** ("node type = installed software; edge transmissible only for a payload-compatible type pair"). Monoculture-within-segments = assortative type mixing, already modeled here. Must-cite.
- **Karrer & Newman, "Competing epidemics on complex networks," PRE 84:036106 (2011); arXiv:1105.3424.** Mutually-immunizing diseases; dominance transition. → *adjacent* (relevant only if SERUM models multiple simultaneous payloads).
- **Salehi et al., "Spreading Processes in Multilayer Networks," IEEE TNSE 2(2):65 (2015); arXiv:1405.4329.** Survey of multilayer contagion. → *framing antecedent* for "payload-specific subgraph = a layer."
- **Sahneh & Scoglio, "Competitive epidemic spreading over arbitrary multilayer networks," PRE 89:062817 (2014); arXiv:1308.4880.** Per-layer distinct transmission routes. → *optional depth*.

### 1c. Malware/worm-specific propagation
- **Kephart & White, "Directed-graph epidemiological models of computer viruses," IEEE S&P (Oakland) 1991.** The historical root of "malware = epidemic on a graph." → *antecedent* (origin of the lineage).
- **Staniford, Paxson & Weaver, "How to 0wn the Internet in Your Spare Time," USENIX Security 2002.** Code Red/Nimda; hit-list, permutation, flash worms. → *canonical must-cite*; assumes a homogeneous vulnerable population reachable by scanning — SERUM's heterogeneity (software-gated) is the differentiator.
- **Zou, Gong & Towsley, "Code Red Worm Propagation Modeling and Analysis" (two-factor model), ACM CCS 2002.** Homogeneous-mixing worm baseline. → *differentiator* (fixed vulnerable population N; SERUM structuralizes it).
- **Chen, Gao & Kwiat, "Modeling the Spread of Active Worms" (AAWP), IEEE INFOCOM 2003.** Discrete-time random/local-subnet scanning. → *differentiator*; its local-subnet variant is the closest classical nod to spatial structure, still no per-host vulnerability gate.
- **Zou, Towsley & Gong, "Email/Topological Worm Modeling and Defense," IEEE TDSC 4(2):105 (2007).** Worms on a *logical* graph across topologies; selective immunization. → *antecedent* to SERUM's contagion-graph view; SERUM further filters the logical graph by software vulnerability.
- Empirical anchors: **Moore et al., "Code-Red: a case study…," ACM IMW 2002**; **Moore et al., "Inside the Slammer Worm," IEEE S&P Mag. 1(4):33 (2003).** → *motivation*: real worms were vulnerability-specific (IIS; MS-SQL), i.e. the vulnerable subpopulation is the true substrate.

### 1d. Software diversity / monoculture
- **O'Donnell & Sethu, "On Achieving Software Diversity … Distributed Coloring," ACM CCS 2004.** Assign diverse software by graph coloring; a worm crosses an edge only between compatible (same-package) nodes. → **the closest security-side antecedent to SERUM's core mechanism** — vulnerability-gated propagation on a type-labeled graph. Must-cite; SERUM's delta is analytic/empirical modeling of monoculture segments + payload subgraphs (vs a defensive coloring objective).
- **Geer et al., "CyberInsecurity: The Cost of Monopoly," CCIA report (2003).** Monoculture concentrates shared vulnerabilities. → *conceptual origin* of "monoculture = systemic risk." (CORRECTION/CAVEAT: a report, byline varies across copies — verify against the CCIA/Schneier PDF before final citation.)
- **Chen, Garcia-Lebron, Sun, Cho & Xu, "Quantifying Cybersecurity Effectiveness of Software Diversity," arXiv:2111.10090 (2021)** and the dynamic-diversity companion **arXiv:2112.07826 (IEEE TDSC).** Simulation-based quantification; diversity is not always net-beneficial. → *modern contrast* citation.

### 1e. Epidemiology of lateral movement (the enterprise analog)
- **Powell, "The epidemiology of lateral movement…," arXiv:1903.07741 (2019).** Adversary as contagion over a Windows authentication graph; the "gate" is credential caching. → **structurally identical must-cite**: contagion confined to an attribute-gated subgraph.
- **Hagberg, Lemons, Kent & Neil, "Connected Components and Credential Hopping in Authentication Graphs," IEEE SITIS 2014.** Component analysis bounds credential-hopping reach. → *graph-structural antecedent*.
- **Kent, Liebrock & Neil, "Authentication graphs…," Computers & Security 48:150 (2015).** Defines enterprise auth graphs from real logs. → *supporting substrate citation*.

**Honest positioning (Theme 1).** SERUM's propagation model is **not** a new mechanism. Restricting infection to hosts running the exploited software is exactly heterogeneous multitype bond percolation (Allard et al. 2009), itself a case of Newman's (2002) SIR-percolation mapping; the payload-specific subgraph is the type-induced occupied subgraph, and its threshold is the spectral radius of the type-level next-generation matrix already derived there. Segment monoculture is assortative type mixing (Allard et al.), argued qualitatively by Geer et al. (2003) and modeled by O'Donnell & Sethu (2004). The same attribute-gated-subgraph pattern underlies lateral-movement models (Powell 2019). SERUM should frame its model as "a security-operations instantiation and empirical study of multitype-percolation worm spread," not a new propagation theory.

---

## Theme 2 — Network immunization & containment (SERUM's baselines)

### 2a. Targeted immunization by centrality
- **Pastor-Satorras & Vespignani, "Immunization of complex networks," PRE 65:036104 (2002); arXiv:cond-mat/0107066.** Random immunization fails on scale-free nets; targeting high-degree restores a threshold. → *origin of the degree baseline*.
- **Cohen, Erez, ben-Avraham & Havlin, "Breakdown of the Internet under Intentional Attack," PRL 86:3682 (2001).** Removing few high-degree nodes fragments scale-free nets. → *theory for the small-budget regime*.
- **Cohen, Havlin & ben-Avraham, "Efficient Immunization Strategies…," PRL 91:247901 (2003); arXiv:cond-mat/0207387.** **Acquaintance immunization** (immunize a random neighbor). → *source of SERUM's acquaintance baseline*.
- **Kitsak et al., "Identification of influential spreaders…," Nature Physics 6:888 (2010); arXiv:1001.5285.** k-core/k-shell spreaders. → *alternative structural baseline*.
- **Morone & Makse, "Influence maximization … optimal percolation," Nature 524:65 (2015)** and **Morone et al., Sci. Rep. 6:30062 (2016); arXiv:1603.08273.** Collective Influence (CI). → *the strongest structure-only optimizer to position against*.

### 2b. Spectral / eigenvalue containment
- **Wang, Chakrabarti, Wang & Faloutsos, "Epidemic spreading … an eigenvalue viewpoint," IEEE SRDS 2003.** Threshold ≈ 1/λ₁ (largest adjacency eigenvalue). → *justifies the eigen-drop objective SERUM's interventions implicitly move*.
- **Chen, Tong, Prakash et al., "Node Immunization on Large Graphs" (NetShield/NetShield+), IEEE TKDE 28(1):113 (2016);** orig. **Tong et al., ICDM 2010.** Greedy node set that most lowers λ₁. → *canonical spectral node-immunization baseline*.
- **Van Mieghem et al., "Decreasing the spectral radius … by link removals," PRE 84:016101 (2011).** NP-hard; eigenvector-product heuristic. → *origin of SERUM's link-cut heuristic*.
- **Tong et al., "Gelling, and Melting, Large Graphs by Edge Manipulation," ACM CIKM 2012.** Edge-level λ₁ control. → *edge-level analog of SERUM's link-cut*.

### 2c. Influence blocking & connectivity-preserving containment
- **Kempe, Kleinberg & Tardos, "Maximizing the spread of influence…," ACM SIGKDD 2003.** NP-hardness + greedy (1−1/e) via submodularity. → *source of the greedy baseline*.
- **Kimura, Saito & Motoda, "Blocking links to minimize contamination spread," ACM TKDD 3(2):9 (2009)** (AAAI 2008). Dual of influence max: block links to minimize spread. → *closest classical framing of SERUM's link-cut budget*.
- **Matamalas, Arenas & Gómez, "Effective approach to epidemic containment using link equations," Science Advances 4(12):eaau4212 (2018).** Deactivate few links while preserving connectivity. → **closest precedent for coupling containment with connectivity/availability**; SERUM generalizes "preserve connectivity" to an explicit service-availability Pareto.

### 2d. Multi-objective / cost-aware & data-aware immunization
- **Maulana, Kefalas & Emmerich, "Immunization … multiobjective metaheuristics," IEEE SSCI 2017.** Infection vs cost Pareto via GA. → *precedent for Pareto immunization*.
- **Bucur, "Multiple Node Immunisation … Exact Multiobjective Optimisation of Cost and Shield-Value," arXiv:2010.06488 (2020).** Exact cost-vs-eigendrop Pareto fronts. → *direct methodological analog*; SERUM's second axis is availability, not budget cost.
- **Lorch et al., "Stochastic Optimal Control of Epidemic Processes in Networks," arXiv:1810.13043 (NeurIPS 2018 ML4H).** Optimal treatment intensities over time. → *the control-theoretic alternative*.
- **Zhang & Prakash, "Data-Aware Vaccine Allocation Over Large Networks" (DAVA), ACM TKDD 10(2):20 (2015).** Immunize conditioned on the *observed infected* subgraph. → **the nearest prior notion of "data/content-aware" defense** — but DAVA conditions on observed infection *state*; SERUM conditions on the *inferred exploit* and its vulnerable subgraph (a strictly sharper conditioning) and adds availability.

### 2e. Graph dismantling (the aggressive limit)
- **Braunstein, Dall'Asta, Semerjian & Zdeborová, "Network dismantling," PNAS 113(44):12368 (2016); arXiv:1603.08883.** Min node set to fragment a graph (Min-Sum). → *the fragmentation limit SERUM deliberately avoids* (fragmentation destroys availability — motivating the Pareto).
- **Ren, Gleinig, Helbing & Antulov-Fantulin, "Generalized network dismantling," PNAS 116(14):6554 (2019).** Cost-weighted dismantling. → *cost-weighted parallel*, but pure-fragmentation objective.

**Honest positioning (Theme 2).** SERUM claims no novelty in *how* it scores hosts — degree/betweenness/eigenvector/acquaintance/greedy are exactly the established methods above, and its infection-vs-cost Pareto echoes Maulana/Bucur/Lorch. Its two extensions are: (i) **content-awareness** — defend the *inferred payload-specific vulnerable subgraph*, so "important" hosts are the exploitable ones, a sharper conditioning than DAVA's observed-infection state; and (ii) an explicit **infection-vs-availability** objective (service continuity, not generic removal cost). Both sit on top of, and are evaluated against, these baselines.

---

## Theme 3 — Cascade inference, source detection & identifiability (the core novelty's neighborhood)

### 3a. Source detection (WHERE it started — not SERUM)
- **Shah & Zaman, "Rumors in a Network: Who's the Culprit?," IEEE Trans. IT 57(8):5163 (2011); arXiv:0909.4370.** Rumor centrality ML source estimator. → *differentiator*: infers the source node under a *known* process; SERUM infers a CVE label online.
- **Pinto, Thiran & Vetterli, "Locating the Source of Diffusion in Large-Scale Networks," PRL 109:068702 (2012); arXiv:1208.2534.** Source from sparse observer arrival times. → *differentiator* (localizes origin, not exploit).
- **Zhu & Ying, "Information Source Detection in the SIR Model…," IEEE/ACM ToN 24(1):408 (2016); arXiv:1206.5421.** Sample-path / Jordan-center source. → *differentiator*.

### 3b. Learning diffusion structure/parameters (unknown graph — the mirror image of SERUM)
- **Gomez-Rodriguez, Leskovec & Krause, "Inferring Networks of Diffusion and Influence" (NetInf), ACM SIGKDD 2010; ACM TKDD 2012.** Latent diffusion network from cascades. → *differentiator*: recovers edges; SERUM recovers an exploit class with the graph observable.
- **Gomez-Rodriguez, Balduzzi & Schölkopf, "Uncovering the Temporal Dynamics of Diffusion Networks" (NetRate), ICML 2011; arXiv:1105.0697.** Edges + per-edge rates. → *differentiator* (SERUM discriminates *between* processes).
- **Gomez-Rodriguez, Leskovec & Schölkopf, "Structure and Dynamics of Information Pathways" (InfoPath), WSDM 2013; arXiv:1212.1464.** Tracks a time-varying latent graph online. → *differentiator*: "online" = drifting graph, vs SERUM's belief over a fixed exploit.
- **Netrapalli & Sanghavi, "Learning the graph of epidemic cascades," ACM SIGMETRICS 2012; arXiv:1202.1779 ("Finding the Graph of Epidemic Cascades").** Sample complexity to reconstruct the graph. → *differentiator*; cite the SIGMETRICS title, note the arXiv id.

### 3c. Inferring WHICH mechanism from cascade shape (the nearest neighborhood)
- **Harrison, Alabsi Aljundi, Chen, Ravi, Vullikanti, Marathe & Adiga, "Identifying Complicated Contagion Scenarios from Cascade Data" (SCENARIOID), ACM SIGKDD 2023.** Classify a partially observed cascade into its generating *scenario* via hand-crafted structural features. → **the strongest prima facie COLLISION** (same one-sentence pitch). SERUM differs: *online POMDP belief* with a *provable identifiability condition* and *vulnerability-defined* classes, vs *batch feature-engineered classification of intervention regimes* with no guarantee. Cite prominently; state the delta immediately.
- **Cencetti, Contreras, Mancastroppa & Barrat, "Distinguishing simple and complex contagion processes on networks," PRL 130:247401 (2023); arXiv:2301.09407.** Discriminate contagion families from infection order. → *baseline* for mechanism discrimination.
- **Zarezade, Khodadadi, Farajtabar, Rabiee & Zha, "Correlated Cascades: Compete or Cooperate," AAAI 2017; arXiv:1510.00936.** Marked Hawkes model of interacting cascades. → *differentiator*: models interaction between co-spreading cascades; SERUM identifies a single unknown process.

### 3d. Identifiability theory (the theorem's true neighbors)
- **Hoffmann, Basu, Goel & Caramanis, "Learning Mixtures of Graphs from Epidemic Cascades," ICML 2020, PMLR 119:4342; arXiv:1906.06057.** First necessary-and-sufficient conditions to learn a *mixture of two graphs* from cascades; exact on *edge-separated* graphs. → **the nearest identifiability COLLISION.** SERUM differs sharply: Hoffmann's condition is on *latent, hidden* edge structure and needs many cascades; SERUM's is on *observable* node vulnerability profiles (a singleton-intersection / set-containment condition), decides a *categorical* exploit, and holds *online per cascade*.
- **Kiss & Simon, "On Parameter Identifiability in Network-Based Epidemic Models," Bull. Math. Biol. 85 (2023); arXiv:2208.07543.** (CORRECTION: earlier project notes cited this as "Sridhar et al." — that attribution is **unverified/incorrect**; the verified paper is Kiss & Simon.) Strong/weak identifiability of *continuous rate parameters*. → *differentiator*: SERUM gives an exact *combinatorial* criterion for a *discrete* label.
- **Massonis, Banga & Villaverde, "Structural Identifiability and Observability of Compartmental Models of the COVID-19 Pandemic," Annual Reviews in Control 51:441 (2021); arXiv:2006.14295.** Differential-algebra observability tests. → *contrast* (ODE parameter recovery vs set-theoretic condition).

### 3e. Strain identification (WHICH strain — molecular, not topological)
- **Rambaut et al., "A dynamic nomenclature proposal for SARS-CoV-2 lineages," Nature Microbiology 5:1403 (2020); O'Toole et al., PANGOLIN, Virus Evolution 2021.** Lineage assignment from *sequenced genomes*. → *contrast that preempts "isn't this solved?"*: strain ID reads the pathogen's genome; SERUM's defender **cannot** observe the payload and must infer it from who is infected — the security analog of "identify the pathogen without sequencing it."

**Honest positioning (Theme 3).** SERUM sits at the intersection of three lines never combined: source detection answers *where* under a known process; network-inference recovers a *latent graph* under a known family; mechanism-classification labels the *process* but *offline*, from engineered features, without a guarantee. SERUM is the first to (i) treat exploit identity as a *hidden categorical state inferred online* via a POMDP over vulnerability-gated cascades (observation model: an infected host *must* carry the exploited vuln), and (ii) supply an *exact constructive identifiability theorem* — identifiable iff infected profiles intersect in a singleton — a *set-containment condition on observable attributes*, categorically different from Hoffmann's latent-edge identifiability and from ODE parameter identifiability. **The two mandatory citations are SCENARIOID (KDD 2023) and Hoffmann et al. (ICML 2020).**

---

## Theme 4 — Sequential decision-making for cyber defense

### 4a. POMDP / belief-state defense
- **Miehling, Rasouli & Teneketzis, "Optimal Defense Policies for Partially Observable Spreading Processes on Bayesian Attack Graphs," ACM MTD 2015;** journal: **"A POMDP Approach to the Dynamic Defense of Large-Scale Cyber Networks," IEEE TIFS 13(10):2490 (2018).** → **closest published ancestor of SERUM's formulation** (hidden spreading state on a graph + belief-based defender). SERUM's delta: the *payload/exploit identity* is the hidden variable, plus budgeted containment and honeypot sensing.
- **Hu, Zhu & Liu, "Adaptive Cyber Defense Against Multi-Stage Attacks Using Learning-Based POMDP," ACM TOPS 24(1):6 (2020).** RL-POMDP against multi-stage attacks. → *comparable baseline*.
- **Kazeminajafabadi & Imani, "Optimal Joint Defense and Monitoring for Networks Security under Uncertainty: A POMDP-Based Approach," IET Info. Security (2024).** *Jointly* optimizes defense and *monitoring/sensing*. → **strongest related work for SERUM's honeypot-sensing contribution**.
- **Gmytrasiewicz & Doshi, "A Framework for Sequential Planning in Multi-Agent Settings" (I-POMDP), JAIR 24:49 (2005).** → *theoretical foundation* for SERUM's adversarial variant.
- **Shinde, Doshi & Setayeshfar, "Active Deception using Factored Interactive POMDPs to Recognize Cyber Attacker's Intent," arXiv:2007.09512 (2020); AAMAS 2021.** Decoys to infer attacker *intent/type*. → *primary related work for the adversarial/honeypot variant*; SERUM infers *which exploit*, not intent.
- **Hammar & Stadler, "Intrusion Prevention through Optimal Stopping," arXiv:2111.00289; IEEE TNSM 19(3) (2022).** Belief-state RL intrusion response, threshold policies. → *nearest belief-state RL response baseline*.
- **Kreidl & Frazier, "Feedback Control Applied to Survivability…," IEEE Trans. Reliability 53(1):148 (2004).** (CORRECTION: earlier notes said "Kreidl & Willsky" — **incorrect**; the network-defense paper is Kreidl & **Frazier**. Willsky co-authored only Kreidl's *decentralized detection* work.) → *historical control-theoretic precursor* for the cost/budget tradeoff.

### 4b. Autonomous cyber-operations gyms / testbeds
- **CybORG — Standen, Lucas, Bowman, Richer, Kim & Marriott, arXiv:2108.09118 (2021)** (earlier arXiv:2002.10667, 2020). → *substrate paradigm*; SERUM formalizes containment-under-unobserved-payload as a POMDP rather than a general gym.
- **CAGE Challenge 4 — Kiely et al., AI Magazine (2025), doi:10.1002/aaai.70021; github.com/cage-challenge/cage-challenge-4.** MARL, segmented defense. → *differentiator*: CC4 stresses multi-agent scalability; SERUM centers single-defender belief over a hidden payload.
- **Microsoft CyberBattleSim (2021), github.com/microsoft/CyberBattleSim.** Attacker-focused lateral-movement gym; defender detects/evicts with no belief over the active exploit. → *differentiator*.
- **Yawning Titan — Andrew, Spillard, Collyer & Dhir, arXiv:2207.12355 (Dstl, 2022).** Abstract graph defense gym; probabilistic red, node-compromise counts. → *differentiator* (abstracts away exploit identity).
- **FARLAND — Molina-Markham, Miniter, Powell & Ridley, arXiv:2103.07583 (MITRE, 2021).** Environment/curriculum design for ACD. → *differentiator* (env design, not a decision-theoretic formulation).
- **CyGym — Lanier & Vorobeychik, arXiv:2506.21688 (2025).** **THE nearest system.** Verified from the paper: (a) vulnerability-gated spread **YES** ("if xᵢ ∉ Xₑ, the exploit fails"); (b) budget **PARTIAL** (per-action costs, *no pooled budget cap*); (c) online inference **NO** — a *static, common-knowledge distribution over zero-days*, PSRO equilibrium computed offline, defender policy *independent of the realized zero-day*. → **cite prominently; SERUM's online belief update + honeypot sensing + inference-evasion attacker are genuine, verified differentiators.**

### 4c. Security games, moving-target defense, deception
- **Tambe, "Security and Game Theory," Cambridge Univ. Press (2011);** **Paruchuri et al., DOBSS, AAMAS 2008;** **Kiekintveld et al., "Computing Optimal Randomized Resource Allocations for Massive Security Games," AAMAS 2009.** → *Stackelberg security-game foundations* SERUM's adversarial variant adopts.
- **Sengupta et al., "A Survey of Moving Target Defenses for Network Security," IEEE COMST 22(3):1909 (2020); arXiv:1905.00964.** → *positions SERUM's dynamic containment/sensing as proactive defense*.
- **Schlenker et al., "Deceiving Cyber Adversaries: A Game Theoretic Approach," AAMAS 2018;** **Durkota et al., "Optimal Network Security Hardening Using Attack Graph Games," IJCAI 2015;** **Carroll & Grosu, "A Game Theoretic Investigation of Deception in Network Security," Security & Comm. Networks 4(10):1162 (2011).** → *honeypot/deception-game antecedents*; SERUM makes deception a *sensing action feeding belief updates*.

### 4d. Estimation-evasion vs detection-evasion (SERUM's adversary)
- **Shokri et al., "Protecting Location Privacy: Optimal Strategy against Localization Attacks," ACM CCS 2012.** Optimal obfuscation vs an *inference* (localization) adversary. → **direct precedent for evade-ESTIMATION framing.**
- **Fanti, Kairouz, Oh & Viswanath, "Spy vs. Spy: Rumor Source Obfuscation," ACM SIGMETRICS 2015 (Best Paper); arXiv:1412.8439** (journal "Hiding the Rumor Source," arXiv:1509.02849). Adaptive diffusion defeats a source *estimator*. → *second evade-estimation precedent*.
- **Biggio et al., "Evasion Attacks against Machine Learning at Test Time," ECML PKDD 2013; arXiv:1708.06131.** Evade a *detector* (decision boundary). → **the contrast pole**: SERUM's adversary evades the defender's *inference/estimation* of the payload, not a binary detector.

### 4e. Active hypothesis testing / value of information / dual control (SERUM's sensing)
- **Chernoff, "Sequential design of experiments," Ann. Math. Stat. 30(3):755 (1959).** Root of adaptive experiment selection. → *historical antecedent*.
- **Naghshvar & Javidi, "Active Sequential Hypothesis Testing," Ann. Stat. 41(6):2703 (2013); arXiv:1203.4626.** → **the canonical formalization of SERUM's honeypot-sensing loop** (adaptively pick sensing actions to resolve a hidden hypothesis under cost).
- **Feldbaum, "Dual Control Theory, I–IV," Autom. Remote Control 21–22 (1960–61).** Probe-to-learn vs act-to-control. → *control-theoretic origin* of SERUM's explore/exploit tension. (Per-part pagination varies; verify if exact pages needed.)
- **Krause & Guestrin, "Near-optimal Nonmyopic Value of Information in Graphical Models," UAI 2005; arXiv:1207.1394.** Submodular (1−1/e) sensing selection. → *justifies greedy budgeted honeypot selection with guarantees*.
- **Araya-López, Buffet, Thomas & Charpillet, "A POMDP Extension with Belief-dependent Rewards" (ρ-POMDP), NeurIPS 2010.** (CORRECTION: 4th author is **Charpillet**, not "Sigaud".) Reward on the belief (info gain). → *the modeling primitive for rewarding SERUM's sensing*.
- **Leskovec, Krause, Guestrin, Faloutsos, VanBriesen & Glance, "Cost-effective Outbreak Detection in Networks" (CELF), ACM SIGKDD 2007.** Submodular sensor placement (static). → *the budgeted placement analog*; CELF is SERUM's non-adaptive baseline.
- **Spinelli, Celis & Thiran, "Back to the Source: an Online Approach for Sensor Placement and Source Localization," WWW 2017; arXiv:1702.01056.** Online/adaptive sensor placement. → *closest adaptive-sensing analog* (localizes source; SERUM pins the exploit).

**Honest positioning (Theme 4).** The POMDP-defense, security-game, deception, and active-sensing machinery are all established (Miehling et al.; Tambe; Schlenker et al.; Naghshvar & Javidi). SERUM's contribution is not the machinery but its *object and coupling*: the hidden state is the *exploit*, the observation model is *vulnerability-gating*, sensing is a *honeypot that captures the payload*, and the adversary evades the *inference*. The nearest system, CyGym, is a *static-prior offline-equilibrium* approach without online belief update — the verified gap SERUM fills.

---

## Theme 5 — ML & LLMs for security, and vulnerability data

### 5a. GNN + RL for graph intervention
- **Meirom, Maron, Mannor & Chechik, "Controlling Graph Dynamics with RL and GNNs" (RLGN), ICML 2021, PMLR 139:7565; arXiv:2010.05313.** GNN-ranked RL budgeted intervention on a partially observed diffusion. → **closest methodological precedent; SERUM's learned policy is NOT novel as vanilla GNN-RL.** SERUM's delta: *learning under exploit uncertainty with belief-augmented features*.
- **Fan, Zeng, Sun & Liu, "Finding key players … through deep reinforcement learning" (FINDER), Nature Machine Intelligence 2:317 (2020).** Learned dismantling/immunization. → *establishes "learning to immunize" as prior art*.
- **Ling et al., "Cooperating GNNs with Deep RL for Vaccine Prioritization," IEEE JBHI (2024); arXiv:2305.05163.** Recent GNN+DRL prioritized intervention. → *reinforces the pattern is well-trodden*.

### 5b. LLM agents for cyber defense
- **"Large Language Models are Autonomous Cyber Defenders," arXiv:2505.04843 (IEEE CAI 2025).** LLMs as blue agents in CAGE-4; LLMs underperform trained RL on raw reward. → *prior art for "LLM in the defensive loop"*; SERUM's LLM is *not the actor* (avoids the known weakness) — it supplies a prior.
- **"LLM Integration with RL to Augment Decision-Making in Autonomous Cyber Operations," arXiv:2509.05311 (2025).** LLM informs an RL cyber-defender; faster convergence. → **the most on-point "LLM knowledge accelerating RL defense" precedent**; SERUM differs by emitting a *structured prior over a fixed CVE candidate set*, corrected by a Bayesian tracker.

### 5c. LLMs for CVE triage / CVSS-from-text; LLM-as-prior
- **Shahid & Debar, "CVSS-BERT…," IEEE ICMLA 2021; arXiv:2111.08510.** Predict CVSS vector from CVE text. → *prior art for "derive severity from text"*; SERUM targets a prior over *which CVE is live*, not the CVSS vector.
- **Alam, Bhusal, Nguyen & Rastogi, "CTIBench…," NeurIPS 2024 D&B; arXiv:2406.07599.** LLM CTI benchmark incl. CVE→severity. → *justifies treating the LLM as a noisy prior needing Bayesian correction*.
- **Liu et al., "Exploring ChatGPT's Capabilities on Vulnerability Management," USENIX Security 2024.** LLM triage is useful-but-inconsistent. → *supports the uncertainty-aware wrapper*.
- **Yan et al., "Efficient Reinforcement Learning with Large Language Model Priors," ICLR 2025; arXiv:2410.07927.** LLM output as a Bayesian *prior action distribution* into RL. → **the methodological backbone SERUM instantiates** (LLM-as-prior corrected by learning) — why SERUM's ML machinery is "mostly established."

### 5d. Vulnerability data & scoring (SERUM's grounding)
- **NVD (NIST), nvd.nist.gov; CVE Program (MITRE), cve.org.** CVE IDs + CVSS/CWE/CPE enrichment. → *data-provenance citations*.
- **CVSS v3.1 Specification, FIRST (2019).** Exploitability {AV, AC, PR, UI} + Impact {C, I, A} subscores. → *authority for SERUM's exploitability/impact belief features*. (CVSS v2: Mell, Scarfone & Romanosky, FIRST 2007; CVSS v4.0: FIRST 2023 — canonical, verify byline if cited.)
- **CPE Naming Specification, NIST IR 7695 (Cheikes, Waltermire & Scarfone, 2011), doi:10.6028/NIST.IR.7695.** CPE 2.3 affected-product naming. → *citation for the CPE product grounding*.
- **EPSS — Jacobs, Romanosky, Edwards, Roytman & Adjerid, arXiv:1908.04856 (2019); DTRAP (2021); first.org/epss.** Probabilistic "which vuln will be exploited." → **the incumbent to contrast**: EPSS is *global, static, population-level*; SERUM's prior is *instance-specific over a fixed candidate set*, Bayesian-updated from observations.
- **CISA KEV Catalog** (BOD 22-01, 2021; criteria carried into BOD 26-04, 2026). Actively-exploited CVEs. → *ground-truth label/anchor* for whether the payload prior concentrates on truly-exploited CVEs.

**Honest positioning (Theme 5).** GNN-RL graph intervention (RLGN, FINDER, 2024 GNN+DRL) and LLM-as-Bayesian-prior (Yan et al. ICLR 2025) are established, as is LLM CVE reasoning (CTIBench, CVSS-BERT, Liu et al.) and population-level exploitation priors (EPSS, KEV). SERUM's defensible slice is the *specific coupling*: an **LLM/CVSS threat-intel prior restricted to a data-grounded (NVD/CVE/CPE) candidate set of exploits, injected as belief features into a content-aware containment planner and corrected online by a Bayesian tracker** — acting under quantified payload uncertainty rather than a point estimate. The paper is strongest if it frames the GNN-RL and LLM-prior components as deliberately standard building blocks and concentrates novelty claims on the uncertainty-aware coupling, the identifiability theory, and the real-CVE grounding.

---

## Theme 6 — Group testing, separating systems & combinatorial identification (THE FIELD WE MISSED)

Surfaced late, during a self-grill of the identifiability theory: SERUM's
identifiability result is, formally, a **group-testing / separating-system**
statement. This is a classical, deeply-developed field that the earlier audit
missed entirely. It must be cited (an information-theory reviewer would spot it
immediately), and it *strengthens* SERUM by giving the theorem a rigorous home.

- **Dorfman, "The Detection of Defective Members of Large Populations," Ann. Math. Stat. 14(4):436 (1943).** The origin of group testing: identify defective items by testing pooled subgroups. → *the ancestral framework*.
- **Rényi, "On random generating elements of a finite Boolean algebra" / separating systems (1961).** Families of sets that *separate* every pair of elements. → **SERUM's identifiability condition IS a separating-system condition** (the infected hosts' profiles separate the true CVE from every other).
- **Kautz & Singleton, "Nonrandom binary superimposed codes," IEEE Trans. IT 10(4):363 (1964).** Superimposed codes / *cover-free families*: no codeword covered by the union of `r` others. → **SERUM's confusers are exactly cover-free-family violations** (`carriers(c) ⊆ carriers(c')`).
- **Du & Hwang, "Combinatorial Group Testing and Its Applications," World Scientific (2000).** The canonical monograph (adaptive vs non-adaptive, disjunct/separable matrices, bounds). → *the toolbox* for SERUM's identifiability bounds and constructions.
- **Aldridge, Johnson & Scarlett, "Group Testing: An Information Theory Perspective," Found. Trends Commun. Inf. Theory 15(3–4):196 (2019); arXiv:1902.06002.** Modern survey incl. information-theoretic limits. → *rate/limit results* relevant to how much of an outbreak is needed to identify the exploit.
- **Atia & Saligrama, "Boolean Compressed Sensing and Noisy Group Testing," IEEE Trans. IT 58(3):1880 (2012).** Group testing under observation noise. → **the exact framework for SERUM's imperfect-inventory and belief-poisoning settings** (noisy tests).

**The mapping (and SERUM's genuine twist).**

| SERUM | Group testing |
|---|---|
| identify the payload CVE from infected hosts | identify the *defective* from positive *tests* |
| Theorem 1 (∩ infected profiles = {c*}) | 1-separable / *separating-family* condition |
| confusers (Prop. 3) | *cover-free-family* violations |
| imperfect inventory / deception poisoning | *noisy* group testing (Atia–Saligrama) |
| active honeypot sensing | *adaptive* group testing |
| diversity-for-observability (design) | *separating-family construction* |

**The differentiator SERUM must state.** In classical group testing the *tests are
designed* by the experimenter to be separating. In SERUM the "tests" are the host
vulnerability profiles — **not designed, but given by the fleet's software
distribution — and the "outcomes" (which hosts are infected) are produced by an
adversarial, graph-constrained *spreading process*, observed *online* as the
outbreak grows.** So SERUM is group testing where (i) the pooling matrix is fixed
by nature, (ii) the queries are realised by contagion rather than chosen, and
(iii) an adversary picks the defective to be hard to separate. Positioning SERUM
as "online, graph-induced, adversarial group testing for exploit identification"
is both honest and a genuinely novel cell.

---

## The three nearest neighbors — cite prominently, differentiate in the same breath

| Paper | What it shares with SERUM | The verified gap SERUM fills |
|---|---|---|
| **CyGym** (Lanier & Vorobeychik, 2025) | vulnerability-gated spread + a cost model | **static** common-knowledge zero-day prior, offline PSRO equilibrium, policy *independent of the realized exploit* — **no online belief update, no sensing** |
| **SCENARIOID** (Harrison et al., KDD 2023) | classify which mechanism produced a cascade | *offline, feature-engineered* classification of *intervention regimes*, *no identifiability guarantee*; SERUM is *online POMDP* over *exploits* with a *proved* condition and a *vulnerability-gating* observation model |
| **Hoffmann et al.** (ICML 2020) | necessary-&-sufficient identifiability from cascades | condition on *latent hidden edge structure*, batch, many cascades; SERUM's is *set containment on observable node attributes*, categorical, online per cascade |

---

## Master must-cite list (for `paper/refs.bib`)

Propagation: Newman 2002; Allard et al. 2009; O'Donnell & Sethu 2004; Staniford et al. 2002; Powell 2019.
Immunization: Pastor-Satorras & Vespignani 2002; Cohen et al. 2003; Chen/Tong/Prakash (NetShield) 2016; Matamalas et al. 2018; Morone & Makse 2015; Zhang & Prakash (DAVA) 2015.
Inference/identifiability: **Harrison et al. (SCENARIOID) 2023**; **Hoffmann et al. 2020**; Shah & Zaman 2011; Gomez-Rodriguez et al. (NetInf) 2010; Cencetti et al. 2023; Kiss & Simon 2023.
Cyber-defense decision-making: **Lanier & Vorobeychik (CyGym) 2025**; Miehling et al. 2015/2018; Shinde et al. 2020; Naghshvar & Javidi 2013; Leskovec et al. (CELF) 2007; Shokri et al. 2012; Fanti et al. 2015; Biggio et al. 2013; Tambe 2011.
ML/LLM/data: Meirom et al. (RLGN) 2021; Fan et al. (FINDER) 2020; Yan et al. (LLM priors) 2025; Alam et al. (CTIBench) 2024; EPSS (Jacobs et al.) 2019; CVSS v3.1 (FIRST) 2019; NVD/CVE; NIST IR 7695 (CPE).

## Corrections applied during verification (do not reintroduce)
- "Sridhar et al." network-epidemic identifiability → **Kiss & Simon, Bull. Math. Biol. 2023 (arXiv:2208.07543)** (no verified Sridhar paper).
- ρ-POMDP authors → Araya-López, Buffet, Thomas, **Charpillet** (not Sigaud).
- Feedback-control cyber defense → Kreidl & **Frazier** (IEEE Trans. Reliability 2004), not "Kreidl & Willsky".
- Netrapalli & Sanghavi: cite the SIGMETRICS 2012 title "Learning the graph of epidemic cascades"; arXiv:1202.1779 uses "Finding…".
- Geer et al. 2003 "CyberInsecurity": report, byline varies — verify against the CCIA/Schneier PDF before final citation.
