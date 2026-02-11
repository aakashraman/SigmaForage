"""
SigmaForage CLI - Convert Sigma rules to SIEM queries.
"""

import argparse
import sys
from pathlib import Path

from . import __version__
from .converter import convert_sigma_to_siem
from .siem_backends import SIEM_BACKENDS, SIEM_DISPLAY_ORDER

# ASCII art shown when the tool launches (plain ASCII for all terminals)
BANNER = r"""
  _____ _                    _____
 / ____(_)                  |  ___|__   __ _ _ __ ___
| (___  _ __ ___   __ _ _ __| |_ / _ \ / _` | '_ ` _ \
 \___ \| '_ ` _ \ / _ \ '__|  _| (_) | (_| | | | | | |
  ____) | | | | | |  __/ |  | | \___/ \__, |_| |_| |_|
 |_____/|_| |_| |_|\___|_|  |_|       |___/
     ___
    / _ \__ _ _ __ ___   ___  ___ _ __
   | | | / _` | '_ ` _ \ / _ \/ _ \ '__|
   | |_| | (_| | | | | | |  __/  __/ |
    \___/ \__, |_| |_| |_|\___|\___|_|
             |_|

  One Sigma rule. Every SIEM.
"""


def print_banner() -> None:
    """Print Sigma Forage ASCII art when the CLI launches."""
    print(BANNER)


def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sigmaforage",
        description="SigmaForage — Convert Sigma detection rules into native SIEM/XDR queries. "
        "One Sigma rule. Every SIEM. Built for Detection Engineers, Threat Hunters, & DFIR Practitioners.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sigmaforage -i rule.yml -s splunk
  sigmaforage -i sigma-rules/Windows/proc_creation_win_curl_execution.yml -s splunk -s elasticsearch
  sigmaforage -i /path/to/your/sigma_rule.yml -s azure-sentinel -o splunk_query.txt
  sigmaforage -i rule.yml -s all -o queries.txt
  sigmaforage --interactive
  sigmaforage --list-siem
  sigmaforage --list-pipelines
  sigmaforage --help
        """,
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"SigmaForage {__version__}",
    )
    parser.add_argument(
        "-i", "--input",
        metavar="PATH",
        help="Path to Sigma rule file (YAML). Absolute or relative. Use '-' to read from stdin.",
    )
    parser.add_argument(
        "-s", "--siem",
        dest="siems",
        action="append",
        metavar="SIEM",
        help="Target SIEM platform(s). Repeat for multiple (e.g. -s splunk -s elasticsearch). Use 'all' for all supported.",
    )
    parser.add_argument(
        "-p", "--pipeline",
        default="sysmon",
        help="Processing pipeline (default: sysmon). Use --list-pipelines to see options.",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write output to file. By default prints to stdout.",
    )
    parser.add_argument(
        "--list-siem",
        action="store_true",
        help="List supported SIEM platforms and exit.",
    )
    parser.add_argument(
        "--list-pipelines",
        action="store_true",
        help="List available Sigma processing pipelines and exit.",
    )
    parser.add_argument(
        "--no-header",
        action="store_true",
        help="Do not print SIEM name headers in output (useful when single SIEM).",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Interactive mode: prompt for rule path and SIEM choice if not provided.",
    )
    return parser


def list_siem() -> None:
    print("Supported SIEM / XDR platforms (use -s <id>):\n")
    seen = set()
    for key in SIEM_DISPLAY_ORDER:
        if key in seen:
            continue
        seen.add(key)
        if key not in SIEM_BACKENDS:
            continue
        backend_id, pkg = SIEM_BACKENDS[key]
        print(f"  {key:<22} -> backend: {backend_id}")
    print("\nAliases: elk (elasticsearch), microsoft-sentinel (azure-sentinel), helix (trellix-helix),")
    print("        wazuh/graylog (use elasticsearch backend).")
    print("\nInstall backends: sigma plugin install <backend_id>")


def list_pipelines() -> None:
    print("Common Sigma processing pipelines (use -p <name>):\n")
    print("  sysmon     - Map generic log sources to Sysmon events (default)")
    print("  windows    - Windows logsource to Channel / Windows audit events")
    print("  (Others may be available via sigma-cli; run: sigma list pipelines)")


def interactive_mode() -> tuple[str | None, list[str] | None]:
    """Prompt for Sigma rule input and SIEM choice. Returns (content_or_path, [siem_ids]) or (None, None) on skip."""
    print("SigmaForge — Interactive mode (Ctrl+C to exit)\n")
    path_or_paste = input("Sigma rule: path to YAML file, or 'paste' to enter inline, or Enter to skip: ").strip()
    if not path_or_paste:
        return None, None
    if path_or_paste.lower() == "paste":
        print("Paste your Sigma rule (YAML). End with a line containing only '---' or Ctrl+D:")
        lines = []
        try:
            while True:
                line = input()
                if line.strip() == "---":
                    break
                lines.append(line)
        except EOFError:
            pass
        sigma_content = "\n".join(lines)
        if not sigma_content.strip():
            print("No content entered.", file=sys.stderr)
            return None, None
        return sigma_content, []  # caller will treat as content and prompt for SIEM
    # Treat as file path
    p = Path(path_or_paste)
    if not p.exists():
        print(f"File not found: {p}", file=sys.stderr)
        return None, None
    sigma_content = p.read_text(encoding="utf-8")
    return sigma_content, []  # will prompt for SIEM


def prompt_siem_choice() -> list[str]:
    """Show numbered SIEM list and return selected SIEM ids."""
    print("\nTarget SIEM(s). Enter numbers (comma-separated) or names (comma-separated), e.g. 1,3,5 or splunk,elasticsearch:")
    for i, sid in enumerate(SIEM_DISPLAY_ORDER, 1):
        if sid in SIEM_BACKENDS:
            print(f"  {i:2}. {sid}")
    raw = input("Choice: ").strip()
    if not raw:
        return []
    chosen = []
    for part in (x.strip().lower() for x in raw.split(",")):
        if part.isdigit():
            idx = int(part)
            if 1 <= idx <= len(SIEM_DISPLAY_ORDER):
                sid = SIEM_DISPLAY_ORDER[idx - 1]
                if sid in SIEM_BACKENDS:
                    chosen.append(sid)
        elif part in SIEM_BACKENDS:
            chosen.append(part)
    return list(dict.fromkeys(chosen))


def run_convert(args: argparse.Namespace) -> int:
    sigma_content = None
    siem_ids_from_interactive = None

    if getattr(args, "interactive", False) and not (args.list_siem or args.list_pipelines):
        content_or_path, siems = interactive_mode()
        if content_or_path is None and siems is None:
            print("No input. Use -i <file> or run with -h for help.", file=sys.stderr)
            return 0
        if content_or_path is not None:
            siem_ids_from_interactive = prompt_siem_choice()
            if not siem_ids_from_interactive:
                print("No SIEM selected.", file=sys.stderr)
                return 2
            sigma_content = content_or_path
            args.input = "-"
            args.siems = siem_ids_from_interactive

    if args.input is None:
        print("Error: -i/--input is required (or use --list-siem / --list-pipelines).", file=sys.stderr)
        return 2

    if args.input == "-":
        sigma_content = sigma_content if sigma_content is not None else sys.stdin.read()
    else:
        path = Path(args.input)
        if not path.exists():
            print(f"Error: File not found: {path}", file=sys.stderr)
            return 2
        sigma_content = path.read_text(encoding="utf-8")

    if not args.siems:
        if getattr(args, "interactive", False):
            print("\nAvailable SIEMs: " + ", ".join(SIEM_DISPLAY_ORDER[:8]) + ", ...")
            choice = input("SIEM(s), comma-separated (e.g. splunk,elasticsearch,azure-sentinel): ").strip()
            if not choice:
                print("Error: No SIEM selected.", file=sys.stderr)
                return 2
            args.siems = [s.strip().lower() for s in choice.split(",")]
        else:
            print("Error: At least one -s/--siem is required.", file=sys.stderr)
            return 2

    # Resolve "all" to unique backend IDs
    if "all" in args.siems:
        siem_ids = list(dict.fromkeys(SIEM_DISPLAY_ORDER))  # preserve order, no dupes
    else:
        siem_ids = list(dict.fromkeys(s.lower() for s in args.siems))

    out_lines = []
    errors = []
    for siem_id in siem_ids:
        if siem_id not in SIEM_BACKENDS:
            errors.append(f"Unknown SIEM: {siem_id}")
            continue
        ok, text = convert_sigma_to_siem(
            sigma_content,
            siem_id,
            pipeline=args.pipeline,
            rule_path=args.input if args.input != "-" else None,
        )
        if not ok:
            errors.append(f"{siem_id}: {text}")
            continue
        if not args.no_header:
            out_lines.append(f"# --- {siem_id.upper()} ---")
        out_lines.append(text)
        out_lines.append("")

    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        if not out_lines:
            return 1

    output = "\n".join(out_lines).strip()
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
        print(f"Wrote {len(siem_ids)} conversion(s) to {args.output}.", file=sys.stderr)
    else:
        print(output)

    return 0 if not errors else 1


def main() -> int:
    print_banner()
    parser = get_parser()
    args = parser.parse_args()

    if args.list_siem:
        list_siem()
        return 0
    if args.list_pipelines:
        list_pipelines()
        return 0

    return run_convert(args)


if __name__ == "__main__":
    sys.exit(main())
