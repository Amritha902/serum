"""Argus: content-aware agentic containment of malware propagation on networks.

The central research claim: a defender that reasons about *what* is spreading
(the payload's target vulnerability) can contain an outbreak far more
efficiently than one that only sees network *structure* -- because malware
only propagates across hosts whose software is actually exploitable.

Package layout
--------------
argus.sim        Heterogeneous network + vulnerability-gated spread simulator.
argus.inference  Bayesian belief over which CVE is being exploited (POMDP core).
argus.baselines  Structure-only interveners (degree, betweenness, ...).
argus.agents     Content-aware interveners that exploit payload semantics.
argus.experiments  Metrics, episode runners, and comparison harness.
"""

__version__ = "0.1.0"
