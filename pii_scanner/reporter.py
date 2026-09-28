"""Reporting utilities — console output and JSON file export."""
import json


def print_report(findings: list) -> None:
    """Print a human-readable PII scan report to stdout.

    Findings are split into two sections: SOURCE (codebase) and LOG (runtime).
    Each finding shows:
      - Trace    : file path + line number
      - Type     : PII category
      - Value    : raw matched value (for confirmation)
      - Masked   : redacted form
      - Context  : the original line where the leak was found
      - Fix Line : paste-ready corrected version of the context line
      - Fix      : actionable remediation advice
    """
    if not findings:
        print("No PII leaks detected.")
        return

    source_findings = [f for f in findings if f.get("origin", "source") == "source"]
    log_findings    = [f for f in findings if f.get("origin") == "log"]

    total = len(findings)
    print(f"\n{total} PII leak(s) found "
          f"({len(source_findings)} in source, {len(log_findings)} in logs):\n")

    separator = "  " + "-" * 60

    if source_findings:
        print("  ══ SOURCE CODE LEAKS ══\n")
        for f in source_findings:
            _print_finding(f, separator)

    if log_findings:
        print("  ══ LOG FILE LEAKS ══\n")
        for f in log_findings:
            _print_finding(f, separator)


def _print_finding(f: dict, separator: str) -> None:
    """Print a single finding block."""
    print(f"  [{f['type']}] {f['file']}:{f['line']}")
    if f["type"] == "RiskyLog":
        print(f"    Pattern  : {f['value']}")
        print(f"    Warning  : {f.get('masked_value', '[INDIRECT LEAK RISK]')}")
    else:
        print(f"    Value    : {f['value']}")
        print(f"    Masked   : {f.get('masked_value', '[REDACTED]')}")
    print(f"    Context  : {f['context']}")
    fix_line = f.get("fix_line", "")
    if fix_line and fix_line != f["context"] and fix_line != f.get("fix", ""):
        print(f"    Fix Line : {fix_line}")
    print(f"    Fix      : {f.get('fix', 'Remove or redact this value.')}")
    print(separator)


def save_json_report(findings: list, output_path: str) -> None:
    """Save the findings list as a JSON file.

    Args:
        findings: List of finding dicts from the scanner.
        output_path: File path to write the JSON report to.
    """
    with open(output_path, "w", encoding="utf-8") as out:
        json.dump(findings, out, indent=2)
    print(f"Report saved to {output_path}")
