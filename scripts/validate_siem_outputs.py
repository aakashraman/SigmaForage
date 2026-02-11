#!/usr/bin/env python3
"""
Validate SIEM query outputs: run conversion for each supported SIEM and report
success/failure. Use this after installing backends (sigma plugin install <backend>)
to verify which SIEMs produce valid output.

Usage (from repo root):
  python scripts/validate_siem_outputs.py
  python scripts/validate_siem_outputs.py --rule sigma-rules/Windows/proc_creation_win_curl_execution.yml
"""

import argparse
import sys
from pathlib import Path

# Allow importing sigmaforge when run from repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sigmaforge.converter import convert_sigma_to_siem
from sigmaforge.siem_backends import SIEM_DISPLAY_ORDER


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate SigmaForage SIEM conversions")
    parser.add_argument(
        "--rule",
        default="sigma-rules/Windows/proc_creation_win_curl_execution.yml",
        help="Path to Sigma rule YAML",
    )
    parser.add_argument(
        "--pipeline",
        default="sysmon",
        help="Sigma pipeline (default: sysmon)",
    )
    args = parser.parse_args()

    rule_path = Path(args.rule)
    if not rule_path.exists():
        print(f"Error: Rule file not found: {rule_path}", file=sys.stderr)
        return 2

    sigma_content = rule_path.read_text(encoding="utf-8")
    print(f"Rule: {rule_path}")
    print(f"Pipeline: {args.pipeline}\n")
    print(f"{'SIEM':<22} {'Status':<6} Output (first 80 chars)")
    print("-" * 100)

    passed = 0
    failed = 0
    for siem in SIEM_DISPLAY_ORDER:
        ok, out = convert_sigma_to_siem(
            sigma_content,
            siem,
            pipeline=args.pipeline,
            rule_path=str(rule_path),
        )
        if ok:
            status = "OK"
            passed += 1
            snippet = (out or "").replace("\n", " ").strip()[:80]
        else:
            status = "FAIL"
            failed += 1
            snippet = (out or "").split("\n")[0].strip()[:80]
        print(f"{siem:<22} {status:<6} {snippet}")

    print("-" * 100)
    print(f"Passed: {passed}  Failed: {failed}")
    if failed > 0:
        print("\nInstall missing backends: sigma plugin install <backend>  (e.g. splunk, elasticsearch, kusto)")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
