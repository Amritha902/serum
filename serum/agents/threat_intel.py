"""Threat-intelligence-grounded agentic layer (novelty N10).

An analyst -- or an LLM reading CVE/CVSS text -- forms a *prior* over which
exploit an adversary is most likely to have weaponised, before any cascade
evidence exists. SERUM folds that prior into the Bayesian exploit belief, giving
the content-aware agent a warm start: it defends the right vulnerable subgraph
from step one instead of waiting for the outbreak to reveal the target.

Two implementations, one interface:
  * ``threat_intel_weights`` -- offline, deterministic: weaponizability from CVSS
    (severity x exploitability, already encoded in per-CVE beta). Always available.
  * ``llm_rank_cves`` -- optional: if ANTHROPIC_API_KEY is set, asks Claude to
    rank candidate CVEs by worm-weaponizability from their descriptions, and uses
    that as the prior. Falls back to the offline weights otherwise, so the agent
    is fully functional with no API access.

The agent itself (`ThreatIntelAgent`) is the content-aware agent with a
threat-intel prior -- an LLM/analyst signal feeding a rigorous belief-planning
loop, rather than an LLM improvising actions.
"""

from __future__ import annotations

import os

import numpy as np

from serum.agents.content_aware import ContentAwareAgent


def threat_intel_weights(universe) -> np.ndarray:
    """Prior weights over CVEs from CVSS-derived weaponizability (higher
    severity / exploitability -> more likely to be the payload)."""
    w = np.asarray(universe.beta, dtype=float)
    w = (w - w.min()) + 1e-3
    return w / w.sum()


def llm_rank_cves(records_by_index, model: str = "claude-opus-4-8") -> np.ndarray | None:
    """Ask an LLM to rank candidate CVEs by worm-weaponizability from their text.

    ``records_by_index`` maps CVE index -> a CVERecord (id, severity, attack
    vector, description-derived fields). Returns a normalised prior over indices,
    or None if no API key / SDK is available (caller falls back to CVSS weights).

    This keeps the LLM in a *grounded* role: it emits a prior over a fixed,
    known candidate set, which the Bayesian tracker then corrects with evidence
    -- so a hallucinated ranking is washed out by the cascade, never acted on
    blindly.
    """
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    try:  # pragma: no cover - exercised only with an API key present
        import json

        import anthropic

        items = [
            {"index": i,
             "cve": r.cve_id,
             "severity": r.severity,
             "attack_vector": r.attack_vector.value,
             "attack_complexity": r.attack_complexity,
             "base_score": r.base_score}
            for i, r in sorted(records_by_index.items())
        ]
        client = anthropic.Anthropic()
        prompt = (
            "You are a threat-intel analyst. Given these candidate CVEs, output a "
            "JSON object mapping each index to a weaponizability score in [0,1] "
            "for a self-propagating network worm (favor network vector, low "
            "complexity, high severity). Return ONLY JSON {index: score}.\n\n"
            + json.dumps(items)
        )
        msg = client.messages.create(
            model=model, max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        text = msg.content[0].text
        scores = json.loads(text[text.index("{"): text.rindex("}") + 1])
        n = len(records_by_index)
        w = np.array([float(scores.get(str(i), scores.get(i, 0.0))) for i in range(n)])
        w = np.clip(w, 0, None) + 1e-3
        return w / w.sum()
    except Exception:
        return None


class ThreatIntelAgent(ContentAwareAgent):
    """Content-aware agent warm-started by a threat-intel prior over the exploit."""

    name = "content-aware+intel"

    def __init__(self, g, use_llm: bool = False, **kw):
        prior = "threat_intel"
        if use_llm:
            uni = g.graph.get("vuln_universe")
            if uni is not None:
                # map index -> a lightweight record view for the LLM ranker
                recs = getattr(uni, "records_by_index", None)
                if recs is not None:
                    w = llm_rank_cves(recs)
                    if w is not None:
                        prior = w
        super().__init__(g, prior=prior, **kw)
