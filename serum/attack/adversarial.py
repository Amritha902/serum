"""Adversarial payload design: choose the exploit to defeat the inference.

SERUM's defender wins by *identifying* the exploit from the cascade. A strategic
attacker (the follower in a Stackelberg game whose leader is the content-aware
defender) can attack that inference directly: pick a payload that is
non-identifiable -- a CVE whose carriers are a subset of a more prevalent CVE's
carriers -- so that, by the identifiability theorem, the defender's belief can
never single it out and must hedge across confusers. This is evasion of the
defender's *estimator*, not merely of a detector (cf. Fanti et al. 2015; Shokri
2015), and it is exactly the residual-ambiguity structure characterised in
docs/THEORY.md.

We quantify the *price of inference-evasion*: how much of the content-aware
advantage an attacker can erode by choosing a confusable-but-still-spreading
payload instead of a random one.
"""

from __future__ import annotations

import networkx as nx
import numpy as np

from serum.inference.identifiability import (
    carriers, confusers, reachable_component,
)
from serum.sim.payload import Payload


def payload_identifiability_score(g: nx.Graph, cve: int) -> dict:
    """Diagnostics for how attackable-by-inference a given CVE is."""
    R = reachable_component(g, cve)
    conf = confusers(g, cve)
    return {
        "cve": cve,
        "component": len(R),                 # how far it can spread (attacker wants big)
        "n_confusers": len(conf),            # residual ambiguity (attacker wants big)
        "identifiable": len(conf) == 0,
    }


def select_payload(g: nx.Graph, beta: float, objective: str = "evasive",
                   min_component: int = 20,
                   rng: np.random.Generator | None = None) -> Payload:
    """Choose the attacker's payload.

    objective
    ---------
    "evasive"  : among CVEs that still spread (component >= min_component),
                 maximise residual ambiguity (confusers) so the defender's belief
                 cannot pin the exploit -- the inference-evasion best response.
    "identifiable": the opposite (a control): pick a spreading, easily-identified
                 CVE, which the content-aware defender handles best.
    "spread"   : maximise component size regardless of identifiability.
    """
    rng = rng or np.random.default_rng()
    n = g.graph["n_cves"]
    cands = []
    for c in range(n):
        R = reachable_component(g, c)
        if len(R) < min_component:
            continue
        cands.append((c, len(R), len(confusers(g, c))))
    if not cands:  # fall back to the largest-component CVE
        c = max(range(n), key=lambda c: len(reachable_component(g, c)))
        return Payload(cve=c, beta=_beta_for(g, c, beta))

    if objective == "evasive":
        # maximise confusers, tie-break on spread
        c = max(cands, key=lambda t: (t[2], t[1]))[0]
    elif objective == "identifiable":
        c = min(cands, key=lambda t: (t[2], -t[1]))[0]
    elif objective == "spread":
        c = max(cands, key=lambda t: t[1])[0]
    else:
        raise ValueError(f"unknown objective: {objective!r}")
    return Payload(cve=c, beta=_beta_for(g, c, beta))


def _beta_for(g, cve, beta):
    uni = g.graph.get("vuln_universe")
    return float(uni.beta[cve]) if uni is not None else float(beta)


def evasive_payload(g: nx.Graph, beta: float = 0.35, **kw) -> Payload:
    """Convenience: the inference-evasion best-response payload."""
    return select_payload(g, beta=beta, objective="evasive", **kw)
