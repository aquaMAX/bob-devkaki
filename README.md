# PII Leak Detection Scanner

A Python CLI tool that scans source code and test output for accidental leaks of Personally Identifiable Information (PII) — specifically Malaysian IC numbers (NRIC), credit card numbers, and bank account numbers.

Built with **Test-Driven Development (TDD)**: all 166 tests were written before the implementation.

---

## Features

| PII Type | Detection Method |
|---|---|
| **Malaysian IC / NRIC** | Regex constrained to valid month/day + structural validation |
| **Credit Card Numbers** | Regex for Visa, MasterCard, Amex, Discover + Luhn algorithm |
| **Email Addresses** | RFC-compliant regex matching `local@domain.tld` |
| **Phone Numbers** | Malaysian (`01X-XXXXXXX`, `+60`) and generic international formats |
| **Bank Account Numbers** | Heuristic 10–16 digit pattern (fallback, deduplicated against all above) |
| **Indirect Log Leaks** | Flags `logger.info(f"…{obj}…")` patterns before they reach the log |

- Scans **source code** and **test-run log files** as separate targets with `--log`
- Validates credit card numbers with the **Luhn algorithm** to eliminate false positives
- Validates NRIC format (month, day, state code) for structural correctness
- Reports exact **file path + line number** trace for every leak
- Shows a **masked version** of each value (e.g. `************0366`)
- Generates a **paste-ready Fix Line** — the exact source line with PII replaced by its masked form
- Provides **actionable fix advice** per PII type
- **Dual-mode report** splits findings into `SOURCE CODE LEAKS` and `LOG FILE LEAKS` sections
- Exports findings as a **JSON report** for CI/CD pipeline integration
- Exits with code `1` when leaks are found — drop it into any pipeline gate

---

## Project Structure

```
bob-devkaki/
├── main.py                    # CLI entry point
├── pii_scanner/
│   ├── __init__.py
│   ├── patterns.py            # Regex patterns incl. RISKY_LOG_PATTERN
│   ├── validators.py          # Luhn check + NRIC validation
│   ├── scanner.py             # scan_line / scan_file / scan_directory (origin param)
│   ├── masker.py              # mask_value, fix_advice, generate_fix_line
│   └── reporter.py            # Dual-mode console output + JSON export
└── tests/
    ├── test_patterns.py             # 16 tests — NRIC/CC/account regex
    ├── test_patterns_email_phone.py # 22 tests — email + phone regex
    ├── test_validators.py           # 17 tests — Luhn + NRIC validation
    ├── test_scanner.py              # 23 tests — scanning + masked fields
    ├── test_scanner_email_phone.py  # 17 tests — email + phone scanning
    ├── test_masker.py               # 12 tests — masking + fix advice
    ├── test_masker_email_phone.py   # 14 tests — email + phone masking
    ├── test_reporter.py             # 14 tests — output formatting
    ├── test_fix_line.py             #  8 tests — generate_fix_line
    ├── test_risky_log.py            # 15 tests — indirect log leak detection
    └── test_dual_mode.py            # 11 tests — origin field + dual-mode report
```

---

## Installation

No external dependencies are required beyond `pytest` for running tests.

```bash
# Clone and enter the project
git clone <repo-url>
cd bob-devkaki

# Install test runner (only needed for running tests)
pip install pytest
```

---

## Usage

### Scan source code only

```bash
python main.py ./my_project
```

### Scan source code + log files (dual-mode)

```bash
python main.py ./src --log app.log --log logs/
```

### Scan a single source file

```bash
python main.py src/service.py
```

### Save findings to a JSON report

```bash
python main.py ./src --log app.log --output report.json
```

### Example output

```
6 PII leak(s) found (5 in source, 1 in logs):

  ══ SOURCE CODE LEAKS ══

  [RiskyLog] src/service.py:10
    Pattern  : logger.info(f"Processing {customer}")
    Warning  : [INDIRECT LEAK RISK]
    Context  : logger.info(f"Processing {customer}")
    Fix      : This log call interpolates a variable that may contain PII.
               Wrap the logged object with a masking helper before logging,
               or log only safe scalar fields (e.g. customer.id, not customer).
  ------------------------------------------------------------
  [NRIC] src/models/user.py:14
    Value    : 900101-01-1234
    Masked   : 90****-**-****
    Context  : test_ic = "900101-01-1234"
    Fix Line : test_ic = "90****-**-****"
    Fix      : Remove the hardcoded IC number. Store test identifiers in
               environment variables or a secrets vault.
  ------------------------------------------------------------
  [Email] src/notify.py:8
    Value    : admin@company.com
    Masked   : *****@company.com
    Context  : recipient = "admin@company.com"
    Fix Line : recipient = "*****@company.com"
    Fix      : Remove or redact the email address. Use placeholder addresses.
  ------------------------------------------------------------

  ══ LOG FILE LEAKS ══

  [CreditCard] logs/app.log:42
    Value    : 4532015112830366
    Masked   : ************0366
    Context  : card_number=4532015112830366
    Fix Line : card_number=************0366
    Fix      : Tokenise or remove the card number. Never store raw card data.
  ------------------------------------------------------------
```

### JSON report format

```json
[
  {
    "type": "NRIC",
    "value": "900101-01-1234",
    "masked_value": "90****-**-****",
    "fix": "Remove the hardcoded IC number. Store test identifiers in environment variables or a secrets vault, and use anonymised/synthetic values in test fixtures.",
    "file": "src/models/user.py",
    "line": 14,
    "context": "test_ic = \"900101-01-1234\""
  }
]
```

---

## Running Tests

```bash
python -m pytest tests/ -v
```

Expected output: **166 passed**

```
tests/test_fix_line.py::TestGenerateFixLine::test_replaces_nric_in_context PASSED
tests/test_risky_log.py::TestRiskyLogPattern::test_matches_logger_info_fstring PASSED
tests/test_risky_log.py::TestScanLineRiskyLog::test_detects_risky_log_as_finding PASSED
tests/test_dual_mode.py::TestFindingOriginField::test_source_scan_findings_have_origin_source PASSED
tests/test_dual_mode.py::TestDualModeReport::test_report_shows_source_leaks_section PASSED
...
========================= 166 passed in 0.21s =========================
```

---

## Supported File Types

The scanner targets common source and data file extensions:

`.py` `.js` `.ts` `.java` `.go` `.txt` `.log` `.json` `.xml` `.csv` `.env` `.yaml` `.yml` `.toml` `.ini` `.cfg` `.sql`

Binary files and unsupported extensions are silently skipped.

---

## CI/CD Integration

The tool exits with code `1` when any PII is found, making it suitable as a pipeline gate:

```yaml
# Example GitHub Actions step
- name: Scan for PII leaks
  run: python main.py ./src --output pii-report.json
```

---

## Detection Details

### NRIC (Malaysian IC Number)
Format: `YYMMDD-SS-NNNN` or `YYMMDDSSNNNN`

- Year: any two digits
- Month: `01`–`12` (enforced by regex)
- Day: `01`–`31` (enforced by regex)
- State code: `01`–`99` (must be non-zero)

### Credit Card Numbers
Supported networks: Visa, MasterCard, American Express, Discover.
Accepts digits with optional spaces or dashes (e.g. `4532 0151 1283 0366`).
All matches are validated with the **Luhn algorithm** — random digit strings of the right length will not produce false positives.

### Bank Account Numbers
10–16 consecutive digits that do not overlap with an already-detected NRIC or credit card number on the same line.
This is a heuristic — review findings in context before acting on them.

---

## Masking Rules

Each finding includes `masked_value` and `fix_line` fields:

| PII Type | Masking Strategy | Example |
|---|---|---|
| NRIC | Keep year (first 2 digits), mask remaining 10 | `90****-**-****` |
| Credit Card | Keep last 4 digits, mask all others | `************0366` |
| Email | Mask local part, keep domain | `*****@company.com` |
| Phone Number | Keep last 4 digits, mask all others (preserving separators) | `+*******6789` |
| Account Number | Keep last 4 digits, mask all others | `**********1234` |
| RiskyLog | N/A — warning only | `[INDIRECT LEAK RISK]` |

The `fix_line` field contains the **original source line with the raw PII replaced by its masked form** — paste it straight back into the file to make a rerun clean.

## Fix Advice

Each finding includes a `fix` field with actionable remediation:

| PII Type | Advice |
|---|---|
| NRIC | Remove hardcoded value; use synthetic test data + environment variables |
| Credit Card | Tokenise via payment vault (Stripe, Braintree); never store raw PANs |
| Email | Use placeholder addresses in tests; store real addresses in secrets manager |
| Phone Number | Use placeholder numbers in tests; store real numbers in secrets manager |
| Account Number | Reference via environment variable or secrets manager |
| RiskyLog | Mask individual fields before logging; use structured logging with field-level redaction |

## Indirect Leak Detection

The scanner catches the **source-side cause** of runtime log leaks — not just the leaked value in the log, but the logging call that will produce it:

```python
# Flagged as RiskyLog ↓
logger.info(f"Processing {customer}")     # whole object interpolated
logger.debug(request.__dict__)            # full request payload
log.error(f"Failed: {e}")                 # exception may contain request body
logger.info("Data: %s", payload)          # %-format with object
logger.info("Result: {}".format(result))  # .format() with object
```

These lines produce no literal PII in the source file — the leak only materialises at runtime. The scanner flags them proactively so they are fixed before a log aggregator ever sees the data.

---

## Development Approach

This project was built using **Test-Driven Development**:

1. **Red** — all 166 tests were written first, against non-existent modules
2. **Green** — implementation was written to make every test pass
3. **Refactor** — validators corrected to match mathematical truth (e.g. Luhn on all-zeros)

Test files in `tests/` serve as the living specification for every behaviour.
