"""Clean raw NVD records into validated, typed ``CVERecord`` rows.

The raw NVD JSON is ragged: a CVE may carry CVSS v3.1, v3.0, v2, or no metrics;
it may be REJECTED/DISPUTED; CPE configurations nest arbitrarily. This module
normalises all of that behind one deterministic function, drops unusable rows,
de-duplicates by CVE id, and reports what it discarded (no silent data loss).
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass

from serum.data.schema import CSV_FIELDS, AttackVector, CVERecord

_CPE_RE = re.compile(r"cpe:2\.3:[aoh]:([^:]+):([^:]+):")  # vendor, product


@dataclass
class CleanStats:
    seen: int = 0
    kept: int = 0
    rejected: int = 0        # withdrawn/disputed CVEs
    no_metrics: int = 0      # no CVSS of any generation
    duplicate: int = 0
    invalid: int = 0

    def as_dict(self):
        return self.__dict__.copy()


def _pick_metric(metrics: dict):
    """Choose the best-available CVSS metric, newest generation first.
    Returns (version, cvssData, exploitability) or (None, None, None)."""
    for key, ver in (("cvssMetricV31", "3.1"),
                     ("cvssMetricV30", "3.0"),
                     ("cvssMetricV2", "2.0")):
        arr = metrics.get(key)
        if arr:
            entry = arr[0]
            return ver, entry.get("cvssData", {}), entry.get("exploitabilityScore")
    return None, None, None


def _extract_products(cve: dict, cap: int = 40) -> tuple:
    """Collect distinct vendor:product pairs from the CPE configurations."""
    products = []
    seen = set()
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                m = _CPE_RE.match(match.get("criteria", ""))
                if not m:
                    continue
                key = f"{m.group(1)}:{m.group(2)}"
                if key not in seen:
                    seen.add(key)
                    products.append(key)
                    if len(products) >= cap:
                        return tuple(products)
    return tuple(products)


def _is_rejected(cve: dict) -> bool:
    status = (cve.get("vulnStatus") or "").lower()
    if "reject" in status or "withdrawn" in status:
        return True
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en" and d.get("value", "").strip().startswith(("** REJECT", "** DISPUTED")):
            return True
    return False


def parse_record(cve: dict) -> CVERecord | None:
    """Parse one raw NVD ``cve`` dict into a CVERecord, or None if unusable."""
    cve_id = cve.get("id")
    if not cve_id:
        return None
    ver, data, exploit = _pick_metric(cve.get("metrics", {}))
    if ver is None:
        return None  # no CVSS at all -> caller counts as no_metrics
    published = (cve.get("published") or "")[:10]  # YYYY-MM-DD

    if ver == "2.0":
        av = data.get("accessVector")
        ac = (data.get("accessComplexity") or "").upper()
        pr = ""  # v2 has no privileges-required concept
        ui = ""
        severity = (cve.get("metrics", {}).get("cvssMetricV2", [{}])[0]
                    .get("baseSeverity", ""))
    else:
        av = data.get("attackVector")
        ac = (data.get("attackComplexity") or "").upper()
        pr = (data.get("privilegesRequired") or "").upper()
        ui = (data.get("userInteraction") or "").upper()
        severity = (data.get("baseSeverity") or "").upper()

    rec = CVERecord(
        cve_id=cve_id,
        published=published,
        cvss_version=ver,
        base_score=float(data.get("baseScore", -1.0)),
        severity=severity,
        attack_vector=AttackVector.parse(av),
        attack_complexity=ac,
        privileges_required=pr,
        user_interaction=ui,
        exploitability=float(exploit) if exploit is not None else -1.0,
        products=_extract_products(cve),
    )
    return rec if rec.valid() else None


def clean_records(raw_cves) -> tuple[list, CleanStats]:
    """Clean a list/iterable of raw NVD ``cve`` dicts. Returns (records, stats)."""
    stats = CleanStats()
    out: list[CVERecord] = []
    seen_ids: set = set()
    for cve in raw_cves:
        stats.seen += 1
        if _is_rejected(cve):
            stats.rejected += 1
            continue
        if not cve.get("metrics"):
            stats.no_metrics += 1
            continue
        rec = parse_record(cve)
        if rec is None:
            # distinguish "no metrics" from "invalid"
            if not _pick_metric(cve.get("metrics", {}))[0]:
                stats.no_metrics += 1
            else:
                stats.invalid += 1
            continue
        if rec.cve_id in seen_ids:
            stats.duplicate += 1
            continue
        seen_ids.add(rec.cve_id)
        out.append(rec)
        stats.kept += 1
    return out, stats


def write_clean_csv(records, path: str) -> None:
    import os
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for r in records:
            w.writerow(r.to_row())


def load_clean_csv(path: str) -> list:
    with open(path, newline="") as f:
        return [CVERecord.from_row(row) for row in csv.DictReader(f)]
