"""Real-data layer: ingest, clean, and validate NVD/CVE vulnerability data, and
turn it into realistic per-host vulnerability profiles for the simulator.

Pipeline
--------
    nvd.NVDClient        -> fetch raw CVE records from the NVD 2.0 API (cached)
    clean.clean_records  -> parse + validate + dedup into typed CVERecord rows
    profiles.build_universe / attach_real_profiles
                         -> map real CVEs (CVSS, CPE products) onto hosts

This replaces the synthetic Zipf vulnerability model with a distribution
derived from real, worm-relevant vulnerabilities (network attack vector, no
user interaction), so the containment results are grounded in real data.
"""

from serum.data.schema import AttackVector, CVERecord
from serum.data.clean import clean_records, load_clean_csv, write_clean_csv
from serum.data.profiles import (
    RealVulnUniverse,
    build_universe,
    attach_real_profiles,
    generate_real_network,
)

__all__ = [
    "AttackVector",
    "CVERecord",
    "clean_records",
    "load_clean_csv",
    "write_clean_csv",
    "RealVulnUniverse",
    "build_universe",
    "attach_real_profiles",
    "generate_real_network",
]
