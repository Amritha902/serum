from pathlib import Path

from scripts.verify_project import build_report

ROOT = Path(__file__).resolve().parent.parent


def test_build_report_identifies_research_status() -> None:
    report = build_report(ROOT)

    assert report["project_name"] == "SERUM"
    assert report["overall_status"] in {"research-prototype", "needs-more-work"}
    assert report["summary"].startswith("SERUM")
    assert "paper/serum.tex" in report["required_files_present"]
    assert "docs/RELATED_WORK.md" in report["required_files_present"]
    assert report["checks"]["reproducibility"]["status"] in {"passed", "failed"}
