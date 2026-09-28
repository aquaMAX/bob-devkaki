"""PII Leak Detection Scanner — CLI entry point."""
import argparse
import os
import sys

from pii_scanner.scanner import scan_directory, scan_file
from pii_scanner.reporter import print_report, save_json_report


def main():
    parser = argparse.ArgumentParser(
        prog="pii-scanner",
        description=(
            "Scan source code and test-run logs for PII leaks "
            "(NRIC, credit card numbers, emails, phone numbers, account numbers). "
            "Traces each leak to its exact file and line, and generates "
            "paste-ready masked fix lines."
        ),
    )
    parser.add_argument(
        "target",
        help="Source file or directory to scan.",
    )
    parser.add_argument(
        "--log",
        metavar="LOG",
        action="append",
        dest="logs",
        default=[],
        help=(
            "Log file or directory to scan as runtime output. "
            "Can be specified multiple times: --log app.log --log logs/"
        ),
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Save findings as a JSON report to this path.",
        default=None,
    )
    args = parser.parse_args()

    findings = []

    # --- Scan source target ---
    if not os.path.exists(args.target):
        print(f"Error: '{args.target}' does not exist.", file=sys.stderr)
        sys.exit(1)

    if os.path.isdir(args.target):
        findings += scan_directory(args.target, origin="source")
    else:
        findings += scan_file(args.target, origin="source")

    # --- Scan log targets ---
    for log_target in args.logs:
        if not os.path.exists(log_target):
            print(f"Warning: log target '{log_target}' does not exist.", file=sys.stderr)
            continue
        if os.path.isdir(log_target):
            findings += scan_directory(log_target, origin="log")
        else:
            findings += scan_file(log_target, origin="log")

    print_report(findings)

    if args.output:
        save_json_report(findings, args.output)

    # Exit with non-zero code when leaks are found (useful in CI pipelines)
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
