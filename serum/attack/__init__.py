"""Adversarial payload design against the defender's inference (novelty N8)."""

from serum.attack.adversarial import (
    evasive_payload,
    payload_identifiability_score,
    select_payload,
)
from serum.attack.deception import choose_decoys

__all__ = ["evasive_payload", "payload_identifiability_score", "select_payload",
           "choose_decoys"]
