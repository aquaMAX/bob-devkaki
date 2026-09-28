"""Compiled regex patterns for PII detection."""
import re

# Malaysia NRIC: YYMMDD-SS-NNNN (with or without dashes)
# Month constrained to 01-12, day to 01-31
NRIC_PATTERN = re.compile(
    r'\b(\d{2})'
    r'(0[1-9]|1[0-2])'
    r'(0[1-9]|[12]\d|3[01])'
    r'-?(\d{2})'
    r'-?(\d{4})\b'
)

# Credit card numbers: Visa, MasterCard, Amex, Discover (13-19 digits, optionally spaced/dashed)
CREDIT_CARD_PATTERN = re.compile(
    r'\b(?:'
    r'4[0-9]{12}(?:[0-9]{3,6})?'           # Visa (13, 16, 19 digits)
    r'|5[1-5][0-9]{14}'                     # MasterCard
    r'|3[47][0-9]{13}'                      # Amex
    r'|6(?:011|5[0-9]{2})[0-9]{12}'        # Discover
    r'|(?:\d[ -]?){13,19}'                  # Generic spaced/dashed fallback
    r')\b'
)

# Bank account numbers: 10-16 contiguous digits (fallback, after CC and NRIC)
ACCOUNT_NUMBER_PATTERN = re.compile(
    r'\b\d{10,16}\b'
)

# Email addresses
EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
)

# Phone numbers: Malaysian (+60 / 01X) and generic international formats
# Matches: +60123456789  012-3456789  (012) 345 6789  +1-800-555-0199
PHONE_PATTERN = re.compile(
    r'(?<!\d)'                          # no leading digit
    r'(?:\+\d{1,3}[\s\-]?)?'           # optional country code
    r'(?:\(?\d{2,4}\)?[\s\-]?)'        # area / prefix (with optional brackets)
    r'\d{3,4}[\s\-]?'                  # middle block
    r'\d{3,5}'                         # last block
    r'(?!\d)'                          # no trailing digit
)

# Risky logging calls — whole objects, f-strings, % and .format() interpolations
# Flags: logger/log/logging . level ( ...variable... )
# These cause indirect leaks: the PII appears only at runtime in log output.
RISKY_LOG_PATTERN = re.compile(
    r'(?:logger|logging|log)\s*\.\s*(?:debug|info|warning|error|critical|exception)'
    r'\s*\('
    r'(?:'
    r'[^)]*\{[^}]*\}'           # f-string / .format() with {} or {variable}
    r'|[^)]*\.format\s*\('      # explicit .format( call on the log string
    r'|[^)]*%\s*\w'             # %-format with a variable argument
    r'|[^)]*,\s*\w'             # positional args: logger.info("msg %s", obj)
    r')'
)
