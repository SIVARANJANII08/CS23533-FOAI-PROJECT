"""
MITRE ATT&CK Rule-Based Navigator
Entry point.

    python main.py                                  interactive menu
    python main.py --file samples/02_brute_force.log  analyse one file and print the report
    python main.py --demo                           built-in malicious-document scenario
    python main.py --list-samples                   list the sample input files

Extra options with --file or --demo:
    --save reports/out.txt     also write the report to a text file
    --chart reports/out.png    also draw the detection chain (needs matplotlib)

Agent orchestration (Module 4): Pranathee H
Input layer, menu and report format: Sivaranjanii M
"""

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(ROOT, "src"))

from knowledge_base import KnowledgeBase          # noqa: E402
from input_parser import (                        # noqa: E402
    parse_file, parse_fact_lines, list_samples, describe_sample,
)
from cli import NavigatorCLI, analyse             # noqa: E402
import report                                     # noqa: E402
import visualize                                  # noqa: E402


# The original hard-coded scenario: a Word document launching encoded
# PowerShell, plus two of the three brute-force signals (a near miss).
DEMO_FACTS = [
    "process_created:powershell.exe",
    "command_line_contains:-EncodedCommand",
    "parent_process:winword.exe",
    "failed_login_count_exceeds:5",
    "same_source_ip:true",
]


def load_kb():
    kb = KnowledgeBase()
    kb.load_rules(os.path.join(ROOT, "data", "rules.json"))
    kb.load_mitigations(os.path.join(ROOT, "data", "mitigations.json"))
    return kb


def run_once(kb, parse_result, save_path=None, chart_path=None):
    """Non-interactive run: analyse, print the report, optionally save."""

    _, data = analyse(kb, parse_result)
    text = report.render(data)
    print(text)

    if save_path:
        report.save(text, save_path)
        print(f"\nReport saved to {save_path}")

    if chart_path:
        if not visualize.matplotlib_available():
            print("\nChart skipped: matplotlib is not installed (pip install matplotlib).")
        else:
            try:
                visualize.draw_chain(data, chart_path)
                print(f"Chart saved to {chart_path}")
            except ValueError as err:
                print(f"\nChart skipped: {err}")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK Rule-Based Navigator (classical rule-based expert system)"
    )
    parser.add_argument("--file", help="input file to analyse (.log, .facts or .txt)")
    parser.add_argument("--demo", action="store_true", help="run the built-in demo scenario")
    parser.add_argument("--list-samples", action="store_true", help="list sample input files")
    parser.add_argument("--save", metavar="PATH", help="write the report to a text file")
    parser.add_argument("--chart", metavar="PATH", help="save the detection chain as a PNG")
    args = parser.parse_args(argv)

    kb = load_kb()

    if args.list_samples:
        for path in list_samples(os.path.join(ROOT, "samples")):
            print(f"  {os.path.relpath(path, ROOT):<36} {describe_sample(path)}")
        return 0

    if args.file:
        try:
            result = parse_file(args.file, kb)
        except (FileNotFoundError, ValueError) as err:
            print(f"Error: {err}")
            return 1
        run_once(kb, result, args.save, args.chart)
        return 0

    if args.demo:
        result = parse_fact_lines(DEMO_FACTS, source="built-in demo", knowledge_base=kb)
        run_once(kb, result, args.save, args.chart)
        return 0

    try:
        NavigatorCLI(kb, ROOT).run()
    except KeyboardInterrupt:
        print("\n  Goodbye.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
