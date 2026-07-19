"""Typed schema for a cleaned CVE record.

One row = one vulnerability, normalised across the three CVSS generations
(v3.1 / v3.0 / v2) that co-exist in NVD. Every field has an explicit type and a
defined "missing" representation so downstream code never trips over the ragged
raw JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum


class AttackVector(str, Enum):
    """CVSS attack vector -- how remote the attacker can be. Only NETWORK-vector
    vulnerabilities are relevant to a self-propagating worm."""
    NETWORK = "NETWORK"
    ADJACENT = "ADJACENT"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def parse(cls, s):
        if not s:
            return cls.UNKNOWN
        s = str(s).upper()
        # CVSS v2 uses ADJACENT_NETWORK; v2 access vector values differ slightly
        if s in ("ADJACENT_NETWORK", "ADJACENT"):
            return cls.ADJACENT
        try:
            return cls(s)
        except ValueError:
            return cls.UNKNOWN


# CSV column order for the cleaned dataset.
CSV_FIELDS = [
    "cve_id", "published", "cvss_version", "base_score", "severity",
    "attack_vector", "attack_complexity", "privileges_required",
    "user_interaction", "exploitability", "products", "n_products",
]


@dataclass
class CVERecord:
    cve_id: str
    published: str                       # ISO date (YYYY-MM-DD), "" if unknown
    cvss_version: str                    # "3.1" | "3.0" | "2.0" | ""
    base_score: float                    # 0.0-10.0, -1.0 if unknown
    severity: str                        # LOW/MEDIUM/HIGH/CRITICAL/""
    attack_vector: AttackVector
    attack_complexity: str               # LOW/HIGH/""
    privileges_required: str             # NONE/LOW/HIGH/""
    user_interaction: str                # NONE/REQUIRED/""
    exploitability: float                # CVSS exploitability subscore, -1 if unk
    products: tuple = field(default_factory=tuple)  # (vendor:product, ...)

    # -- derived -----------------------------------------------------------
    @property
    def n_products(self) -> int:
        return len(self.products)

    def is_worm_relevant(self) -> bool:
        """Remotely self-propagating: network vector, no user interaction, and a
        product it can land on. Attack complexity is allowed to be HIGH (a worm
        may still spread, just less reliably)."""
        return (
            self.attack_vector == AttackVector.NETWORK
            and self.user_interaction in ("NONE", "")
            and self.n_products > 0
        )

    def valid(self) -> bool:
        return bool(self.cve_id) and (self.base_score < 0 or 0.0 <= self.base_score <= 10.0)

    # -- serialisation -----------------------------------------------------
    def to_row(self) -> dict:
        d = asdict(self)
        d["attack_vector"] = self.attack_vector.value
        d["products"] = "|".join(self.products)
        d["n_products"] = self.n_products
        return {k: d[k] for k in CSV_FIELDS}

    @classmethod
    def from_row(cls, row: dict) -> "CVERecord":
        prods = tuple(p for p in (row.get("products") or "").split("|") if p)
        return cls(
            cve_id=row["cve_id"],
            published=row.get("published", ""),
            cvss_version=row.get("cvss_version", ""),
            base_score=float(row["base_score"]) if row.get("base_score") not in (None, "") else -1.0,
            severity=row.get("severity", ""),
            attack_vector=AttackVector.parse(row.get("attack_vector")),
            attack_complexity=row.get("attack_complexity", ""),
            privileges_required=row.get("privileges_required", ""),
            user_interaction=row.get("user_interaction", ""),
            exploitability=float(row["exploitability"]) if row.get("exploitability") not in (None, "") else -1.0,
            products=prods,
        )
