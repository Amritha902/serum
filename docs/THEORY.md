# SERUM — Identifiability of the Unobserved Exploit

This note states and proves the identifiability results that underpin SERUM's
inference. The point of difference from prior cascade-mixture identifiability
(Hoffmann et al., ICML 2020, which gives a spectral/edge-separation condition on
*latent* graphs) is that here the propagation subgraph is fixed by **observable**
node attributes, so identifiability collapses to a **checkable combinatorial
condition on vulnerability profiles**. Every claim below is validated empirically
at 100% agreement with the Bayesian belief in `scripts/identifiability.py`.

## Setup and notation

- Host graph `G = (V, E)`. Each host `v` carries a vulnerability profile
  `X(v) ⊆ C` over a finite CVE universe `C`.
- `carriers(c) = { v : c ∈ X(v) }`; the **vulnerable subgraph** `G[c]` is induced
  by `carriers(c)`.
- A worm has an unknown target `c* ∈ C`. Propagation is **gated**: an infected
  host may infect a neighbour `w` only if `c* ∈ X(w)`. Hence every
  propagation-infected host lies in `carriers(c*)`.
- The defender observes the infected set `I ⊆ V` (noiseless case) and the static
  profiles `X`, but not `c*`.

## Proposition 1 (exact posterior support)

*After observing a propagation-infected set `I`, the set of CVEs consistent with
the observation is exactly*
`supp(I) = ⋂_{v ∈ I} X(v).`

**Proof.** A CVE `c` could have produced `I` only if every host in `I` is
exploitable by `c` (gating), i.e. `c ∈ X(v)` for all `v ∈ I`, i.e.
`c ∈ ⋂_{v∈I} X(v)`. Conversely any such `c` is consistent with `I` since gating
imposes no other constraint on the identity of the exploit. ∎

The Bayesian belief in `serum/inference/belief.py` (hard mode) maintains exactly
this set; `support_over(G, I)` computes it.

## Proposition 2 (saturation limit)

*Let `R` be the connected component of `G[c*]` containing the seeds. A
deterministic (or, a.s. as `β→1`) outbreak infects exactly `R`, and then*
`supp(I) = supp(R) = ⋂_{v ∈ R} X(v).`

**Proof.** Gating confines infection to `carriers(c*)`; edges within that set
transmit with probability `β`, so with `β=1` the reachable set from the seeds is
precisely their connected component `R` in `G[c*]`. Apply Proposition 1 with
`I = R`. ∎

## Theorem 1 (identifiability)

*The exploit `c*` is identifiable from a saturating outbreak over `R` iff*
`⋂_{v ∈ R} X(v) = { c* }.`

**Proof.** `c* ∈ supp(R)` always (every host of `R` carries `c*`). By
Proposition 2 the observer learns `supp(R)` exactly and nothing more, so `c*` is
uniquely determined iff `supp(R)` is the singleton `{c*}`; otherwise every
`c' ∈ supp(R)\{c*}` is observationally indistinguishable from `c*`. ∎

## Proposition 3 (confusability = subset order)

*Define `c'` to be **confusable** with `c` if some saturating `c`-outbreak cannot
exclude `c'`. Then `c'` is confusable with `c` over component `R` iff
`R ⊆ carriers(c')`. Globally (over the largest component, or any `R`),*
`carriers(c) ⊆ carriers(c') ⟹ c' is confusable with c for every c-outbreak.`

**Proof.** `c'` survives observation of `R` iff `c' ∈ supp(R)`, i.e.
`c' ∈ X(v)` for all `v ∈ R`, i.e. `R ⊆ carriers(c')`. If
`carriers(c) ⊆ carriers(c')` then every host reachable by a `c`-outbreak carries
`c'`, so `R ⊆ carriers(c) ⊆ carriers(c')` for any such `R`. ∎

### Corollary (confusability graph)

Order CVEs by the subset relation on carrier sets. Build the directed graph `H`
with `c → c'` iff `carriers(c) ⊆ carriers(c')`, `c ≠ c'`
(`confusability_graph`). Then **`c` is globally identifiable iff it has no
out-neighbour** — no other CVE's carrier set is a superset of its own. Intuition:
a *stealthier* (less prevalent) exploit is easy to confuse with the popular
services its victims also run; a *distinctive* exploit whose carriers run no
single common other service is pinned down exactly.

This is why SERUM's agent plans under the full posterior rather than a hard MAP:
when `c*` is non-identifiable, the residual confusers `supp(R)\{c*}` are exactly
the CVEs the agent must hedge across — and, crucially, they all share the victim
set, so acting on any of them defends nearly the same hosts.

## Corollary (robustness to inference-evasion)

An attacker could try to defeat the belief by choosing a *non-identifiable*
payload (novelty N8). Proposition 3 shows this backfires: `c'` confuses `c*`
only if `R ⊆ carriers(c')`, i.e. every victim of `c*` also carries the confuser.
Hence the believed vulnerable set is a *superset* of the true victim set, and a
content-aware action taken under the (confused) belief still covers every host
`c*` can reach. The attacker faces a bind: spreading widely needs a large carrier
set, but a carrier set large enough to matter is hard to hide inside a confuser's
without that confuser being defended too. Empirically
(`scripts/adversarial.py`), an inference-evading attacker does **not** erode the
content-aware advantage — it slightly *increases* it, because evasive payloads
are high-prevalence and produce larger outbreaks that structure-only defenders
handle worse. Inference-evasion is not a winning strategy against SERUM.

## Difference from cascade-mixture identifiability

Hoffmann et al. (ICML 2020) ask when two *latent* graphs generating a cascade
mixture are recoverable, and answer with an edge-separation (connectivity)
condition on those graphs. SERUM's latent object is not a graph but a
**categorical exploit**, and the candidate propagation graphs are not latent —
they are `{ G[c] }`, fixed by observable profiles. Identifiability therefore
reduces to set containment among observable carrier sets (Theorem 1,
Proposition 3), a condition a defender can *evaluate in advance* from its asset
inventory. That checkability — and its coupling to the containment policy — is
the contribution.

## Spread bounds anonymity (a one-sided result — stated honestly)

It is tempting to claim a clean "spread–anonymity duality" (a worm cannot both
spread and hide). **The data does not support the strong version, so we state the
weaker, correct one.**

**Proposition 4 (spread bounds anonymity).** For an exploit `c` with reachable
vulnerable component `R` of size `S(c)=|R|`, the number of confusers obeys
`|confusers(c)| ≤ N(S(c)/n) − 1`, where `N(π) = #{c' : prevalence(c') ≥ π}` is the
prevalence complementary count. In particular, since every confuser `c'` must
satisfy `R ⊆ carriers(c')` and hence `prevalence(c') ≥ S(c)/n`, an exploit that
saturates a large fraction of the fleet is forced toward identifiability: if
`S(c)/n` exceeds the second-largest CVE prevalence, `c` is uniquely identifiable.

**Proof.** Each confuser `c'` satisfies `R ⊆ carriers(c')` (Prop. 3), so
`|carriers(c')| ≥ |R| = S(c)`, i.e. `prevalence(c') ≥ S(c)/n`. The confusers are
therefore a subset of `{c' ≠ c : prevalence(c') ≥ S(c)/n}`, whose size is
`N(S(c)/n) − 1` (excluding `c` itself, which also lies in the set). ∎

**What is NOT true (and why).** Anonymity is *not* monotonically decreasing in
spread. Empirically (`scripts/duality.py`, 480 real-CVE exploits) the spread–
anonymity correlation is mildly **positive** (≈ +0.34), and anonymity *peaks at
moderate prevalence*: a confuser must be a *more-prevalent* CVE whose carriers
nest the victims, so both very rare exploits (few CVEs prevalent enough to nest
them) and near-universal exploits (nothing more prevalent) have few confusers.
The bound in Prop. 4 is therefore **one-sided** — it binds only at the high-
spread extreme, forcing wide outbreaks toward identifiability, while leaving
low/moderate-spread exploits free to be anonymous. The honest operational
takeaway is asymmetric: **a worm that chooses wide reach forfeits anonymity, but
a stealthy worm can stay hidden** — so a defender is most certain of the exploit
exactly when the outbreak is worst (large), which is when identification matters
most. This asymmetry, not a symmetric duality, is the real result.

## Connection to group testing and separating systems

Theorem 1 is, in classical terms, a **group-testing** identifiability condition.
Treat the CVE universe as items with exactly one "defective" (the payload `c*`);
each host is a *test* whose pool is its vulnerability profile `X(v)`, and an
infected host is a *positive test* revealing that its pool contains `c*`. The
condition `⋂_{v∈I} X(v) = {c*}` is exactly the requirement that the observed
tests form a **separating family** for `c*` (Rényi 1961); confusers are
**cover-free-family** violations (Kautz & Singleton 1964), and the imperfect-
inventory / belief-poisoning settings are **noisy group testing** (Atia &
Saligrama 2012). The distinction from classical group testing — and SERUM's
contribution — is that the pooling matrix is **not designed** but fixed by the
fleet's software distribution, and the tests are **not queried** but *realised by
an adversarial, graph-constrained spreading process, observed online*. This
"online, graph-induced, adversarial group testing" framing is the honest home for
the identifiability results; see `docs/LITERATURE_REVIEW.md` (Theme 6).

## Empirical validation

`scripts/identifiability.py` builds real-NVD networks, computes
`is_identifiable` per CVE, then runs a saturating outbreak and checks the
Bayesian belief converges to a singleton **iff** the theorem predicts
identifiability. Agreement: **116/116 = 100%**. On real profiles roughly half of
CVEs are identifiable from a saturating outbreak; the rest have confusers —
more-prevalent CVEs their victims also carry — matching Proposition 3.
