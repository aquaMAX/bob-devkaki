"""Core PII scanning logic — line, file, and directory scanning."""
from pathlib import Path

from .patterns import (
    NRIC_PATTERN, CREDIT_CARD_PATTERN, ACCOUNT_NUMBER_PATTERN,
    EMAIL_PATTERN, PHONE_PATTERN, RISKY_LOG_PATTERN,
)
from .validators import luhn_check, is_valid_nric
from .masker import mask_value, fix_advice, generate_fix_line

# File extensions to scan
SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".java", ".go",
    ".txt", ".log", ".json", ".xml", ".csv", ".env",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".sql",
}


def _make_finding(pii_type: str, raw: str, filepath: str, line_no: int,
                  context: str, origin: str) -> dict:
    """Build a standardised finding dict for a detected PII value."""
    mv = mask_value(pii_type, raw)
    return {
        "type": pii_type,
        "value": raw,
        "masked_value": mv,
        "fix": fix_advice(pii_type),
        "fix_line": generate_fix_line(context, raw, mv),
        "file": filepath,
        "line": line_no,
        "context": context,
        "origin": origin,
    }


def scan_line(line: str, line_no: int, filepath: str, origin: str = "source") -> list:
    """Scan a single line of text for PII.

    Returns a list of finding dicts, each with keys:
      type, value, masked_value, fix, fix_line, file, line, context, origin

    Detection order:
      RiskyLog → Email → NRIC → CreditCard → PhoneNumber → AccountNumber
    RiskyLog does not claim spans (it warns, not redacts).
    Email is matched before digit patterns to avoid bleed.
    """
    ctx = line.strip()
    findings = []
    already_matched_spans = []

    # 0. Risky logging calls — indirect leak risk (source files only)
    if origin == "source":
        for match in RISKY_LOG_PATTERN.finditer(line):
            findings.append({
                "type": "RiskyLog",
                "value": match.group(0).strip(),
                "masked_value": "[INDIRECT LEAK RISK]",
                "fix": fix_advice("RiskyLog"),
                "fix_line": fix_advice("RiskyLog"),  # advice is the fix here
                "file": filepath,
                "line": line_no,
                "context": ctx,
                "origin": origin,
            })
            # RiskyLog does NOT claim spans — literal PII on the same line still fires

    # 1. Email — matched before digit patterns
    for match in EMAIL_PATTERN.finditer(line):
        raw = match.group(0)
        findings.append(_make_finding("Email", raw, filepath, line_no, ctx, origin))
        already_matched_spans.append(match.span())

    # 2. NRIC
    for match in NRIC_PATTERN.finditer(line):
        raw = match.group(0)
        if is_valid_nric(raw):
            findings.append(_make_finding("NRIC", raw, filepath, line_no, ctx, origin))
            already_matched_spans.append(match.span())

    # 3. Credit cards
    for match in CREDIT_CARD_PATTERN.finditer(line):
        digits = "".join(c for c in match.group(0) if c.isdigit())
        if 13 <= len(digits) <= 19 and luhn_check(digits):
            raw_cc = match.group(0).strip()
            findings.append(_make_finding("CreditCard", raw_cc, filepath, line_no, ctx, origin))
            already_matched_spans.append(match.span())

    # 4. Phone numbers — before account numbers to claim digit spans first
    for match in PHONE_PATTERN.finditer(line):
        span = match.span()
        if not any(span[0] < end and span[1] > start for start, end in already_matched_spans):
            raw_phone = match.group(0).strip()
            findings.append(_make_finding("PhoneNumber", raw_phone, filepath, line_no, ctx, origin))
            already_matched_spans.append(span)

    # 5. Account numbers — fallback, only unmatched spans
    for match in ACCOUNT_NUMBER_PATTERN.finditer(line):
        span = match.span()
        if not any(span[0] < end and span[1] > start for start, end in already_matched_spans):
            raw_acc = match.group(0)
            findings.append(_make_finding("AccountNumber", raw_acc, filepath, line_no, ctx, origin))

    return findings


def scan_file(filepath: str, origin: str = "source") -> list:
    """Scan a single file for PII line by line.

    Args:
        filepath: Path to the file to scan.
        origin:   "source" (default) for codebase files, "log" for log files.

    Silently skips files that cannot be opened (permission errors, directories).
    Binary files are read with errors='ignore'.
    """
    results = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, start=1):
                results.extend(scan_line(line, line_no, filepath, origin=origin))
    except (PermissionError, IsADirectoryError, FileNotFoundError, OSError):
        pass
    return results


def scan_directory(root: str, extensions: set = None, origin: str = "source") -> list:
    """Recursively scan all supported files in a directory for PII.

    Args:
        root:       Path to the directory to scan.
        extensions: Set of file extensions to include. Defaults to SUPPORTED_EXTENSIONS.
        origin:     "source" (default) or "log" — attached to every finding.

    Returns:
        List of finding dicts across all scanned files.
    """
    if extensions is None:
        extensions = SUPPORTED_EXTENSIONS

    all_results = []
    for path in Path(root).rglob("*"):
        if path.is_file() and path.suffix.lower() in extensions:
            all_results.extend(scan_file(str(path), origin=origin))
    return all_results
