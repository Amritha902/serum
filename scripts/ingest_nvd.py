#!/usr/bin/env python
"""Ingest -> clean -> profile: build a real NVD-grounded dataset for SERUM.

Fetches CVE records from the NVD 2.0 API (cached to data/raw/nvd/), cleans and
validates them into a tidy CSV (data/clean/cves.csv), prints a data card, and
demonstrates the resulting real-data vulnerability profiles on a sample network.

Usage:
    python scripts/ingest_nvd.py --limit 6000
    python scripts/ingest_nvd.py --limit 6000 --offline   # use cache only
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402

from serum.data.clean import clean_records, load_clean_csv, write_clean_csv  # noqa: E402
from serum.data.nvd import NVDClient  # noqa: E402
from serum.data.profiles import build_universe, generate_real_network  # noqa: E402
from serum.sim.network import cve_prevalence  # noqa: E402

CLEAN_CSV = "data/clean/cves.csv"
CARD = "data/clean/data_card.json"


def data_card(records):
    worm = [r for r in records if r.is_worm_relevant()]
    av = Counter(r.attack_vector.value for r in records)
    ver = Counter(r.cvss_version for r in records)
    sev = Counter(r.severity for r in records if r.severity)
    prods = Counter(p for r in worm for p in r.products)
    scores = [r.base_score for r in records if r.base_score >= 0]
    return {
        "n_records": len(records),
        "n_worm_relevant": len(worm),
        "worm_relevant_frac": round(len(worm) / max(1, len(records)), 3),
        "attack_vector": dict(av),
        "cvss_version": dict(ver),
        "severity": dict(sev),
        "base_score_mean": round(float(np.mean(scores)), 2) if scores else None,
        "unique_products_worm": len(prods),
        "top_products": prods.most_common(15),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=6000, help="CVEs to ingest")
    ap.add_argument("--offline", action="store_true", help="use disk cache only")
    ap.add_argument("--all-history", action="store_true",
                    help="fetch from the oldest CVEs instead of the recent window")
    ap.add_argument("--days", type=int, default=120, help="recent window size (<=120)")
    ap.add_argument("--n-cves", type=int, default=40)
    ap.add_argument("--n-products", type=int, default=80)
    args = ap.parse_args()

    if os.path.exists(CLEAN_CSV) and args.offline:
        print(f"[offline] loading cleaned records from {CLEAN_CSV}")
        records = load_clean_csv(CLEAN_CSV)
    else:
        client = NVDClient()
        params = None
        if not args.all_history:
            params = client.recent_window(days=args.days)
            print(f"fetching up to {args.limit} recent CVEs "
                  f"({params['pubStartDate'][:10]} .. {params['pubEndDate'][:10]}) ...")
        else:
            print(f"fetching up to {args.limit} CVEs from the start of NVD ...")
        raw = client.fetch_raw(limit=args.limit, params=params)
        print(f"  fetched {len(raw)} raw records; cleaning ...")
        records, stats = clean_records(raw)
        print("  clean stats:", json.dumps(stats.as_dict()))
        write_clean_csv(records, CLEAN_CSV)
        print(f"  wrote {len(records)} clean records -> {CLEAN_CSV}")

    card = data_card(records)
    os.makedirs(os.path.dirname(CARD), exist_ok=True)
    with open(CARD, "w") as f:
        json.dump(card, f, indent=2)

    print("\n=== DATA CARD ===")
    print(f"clean records:        {card['n_records']}")
    print(f"worm-relevant:        {card['n_worm_relevant']} "
          f"({100*card['worm_relevant_frac']:.1f}%)")
    print(f"attack vector:        {card['attack_vector']}")
    print(f"cvss version mix:     {card['cvss_version']}")
    print(f"mean base score:      {card['base_score_mean']}")
    print(f"unique worm products: {card['unique_products_worm']}")
    print("top products:")
    for p, c in card["top_products"]:
        print(f"   {c:>5}  {p}")

    # demonstrate real-data profiles on a sample network
    print("\n=== REAL-DATA PROFILES (sample 500-host BA network) ===")
    rng = np.random.default_rng(0)
    uni = build_universe(records, n_products=args.n_products, n_cves=args.n_cves, rng=rng)
    g = generate_real_network(records, n=500, n_cves=args.n_cves,
                              n_products=args.n_products, rng=np.random.default_rng(1))
    prev = cve_prevalence(g)
    order = np.argsort(prev)[::-1]
    print(f"CVE universe size:    {uni.n_cves}")
    print(f"beta range:           [{uni.beta.min():.3f}, {uni.beta.max():.3f}]")
    print(f"prevalence range:     [{prev.min():.2f}, {prev.max():.2f}] "
          f"(fraction of hosts vulnerable)")
    print("most prevalent CVEs (real ids):")
    for i in order[:8]:
        print(f"   prev={prev[i]:.2f}  beta={uni.beta[i]:.3f}  {uni.cve_ids[i]}")
    print(f"\n[data card -> {CARD}]")


if __name__ == "__main__":
    main()
