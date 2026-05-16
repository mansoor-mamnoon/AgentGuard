"""
Generate a standalone HTML report and save to data/report.html.

Reads from data/runs/ (if it exists) and data/calibration_report.json.

CLI::

    uv run python -m eval.run_report
    open data/report.html
"""

from __future__ import annotations

import argparse
from pathlib import Path

from backend.html_report import generate_html_report


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate static HTML report")
    ap.add_argument("--runs_dir", default="data/runs", help="Runs directory")
    ap.add_argument("--calibration", default="data/calibration_report.json")
    ap.add_argument("--output", default="data/report.html")
    args = ap.parse_args()

    runs_dir = Path(args.runs_dir)
    cal_path = Path(args.calibration) if Path(args.calibration).exists() else None

    html = generate_html_report(runs_dir=runs_dir, calibration_path=cal_path)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    print(f"Report saved → {out}")


if __name__ == "__main__":
    main()
