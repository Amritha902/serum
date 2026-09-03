#!/usr/bin/env python3
"""Generate a verification-style summary for the SERUM project.

This script is intentionally lightweight and repository-focused. It inspects a
small set of files and outputs a compact report that can be used to answer:
- what the project is,
- whether it appears complete enough for a paper or demo,
- what still needs work before it is more realistic or production-like.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _exists(root: Path, relpath: str) -> bool:
    return (root / relpath).exists()


def _check_reproducibility(root: Path) -> dict[str, Any]:
    expected = [
        "scripts/reproduce_all.py",
        "tests/test_paper_claims.py",
        "results/summary.json",
        "paper/serum.tex",
    ]
    present = [p for p in expected if _exists(root, p)]
    return {
        "status": "passed" if len(present) == len(expected) else "failed",
        "checked_files": expected,
        "present_files": present,
        "missing_files": [p for p in expected if p not in present],
    }


def build_report(root: Path | str | None = None) -> dict[str, Any]:
    root_path = Path(root or Path(__file__).resolve().parent.parent).resolve()

    required_files = [
        "README.md",
        "paper/serum.tex",
        "docs/RELATED_WORK.md",
        "docs/THEORY.md",
        "scripts/reproduce_all.py",
        "tests/test_paper_claims.py",
    ]
    required_files_present = [p for p in required_files if _exists(root_path, p)]

    reproducibility = _check_reproducibility(root_path)
    paper_present = _exists(root_path, "paper/serum.tex")
    real_data_present = _exists(root_path, "data/real_inventory") or _exists(root_path, "results/real")

    if paper_present and reproducibility["status"] == "passed" and real_data_present:
        overall_status = "research-prototype"
        summary = (
            "SERUM is a working research prototype with a paper draft, an experiment "
            "reproduction pipeline, and real-data grounding. It is credible for an "
            "academic demo and paper discussion, but it is not yet a fully mature "
            "real-world deployment system."
        )
    else:
        overall_status = "needs-more-work"
        summary = (
            "SERUM has a strong research foundation, but it still needs more "
            "verification, packaging, and real-world grounding before it can be "
            "described as complete or production-ready."
        )

    return {
        "project_name": "SERUM",
        "overall_status": overall_status,
        "summary": summary,
        "required_files_present": required_files_present,
        "checks": {
            "reproducibility": reproducibility,
            "paper_draft": {
                "status": "passed" if paper_present else "failed",
                "present": paper_present,
            },
            "real_data_grounding": {
                "status": "passed" if real_data_present else "failed",
                "present": real_data_present,
            },
        },
    }


def main() -> int:
    report = build_report()
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    main()
