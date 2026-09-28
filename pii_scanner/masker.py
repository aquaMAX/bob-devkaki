"""PII masking — produce a redacted form of each value and actionable fix advice."""


def generate_fix_line(context: str, raw_value: str, masked_value: str) -> str:
    """Return a paste-ready corrected version of a source/log line.

    Replaces every occurrence of raw_value in context with masked_value so the
    developer can copy the result straight back into their code or log config.

    Args:
        context:      The original source line containing the PII.
        raw_value:    The exact PII string that was detected.
        masked_value: The masked replacement (from mask_value()).

    Returns:
        The context line with all occurrences of raw_value substituted.
        Returns context unchanged if raw_value is not found in it.
    """
    if not context or raw_value not in context:
        return context
    return context.replace(raw_value, masked_value)


def mask_value(pii_type: str, value: str) -> str:
    """Return a masked version of the PII value.

    Masking rules:
      NRIC        — keep first 2 digits (year), mask rest: "90****-**-****"
      CreditCard  — keep last 4 digits, mask all others: "************0366"
      AccountNumber — keep last 4 digits, mask all others: "******7890"
      Unknown     — fully replace with "[REDACTED]"
    """
    if pii_type == "NRIC":
        return _mask_nric(value)
    if pii_type == "CreditCard":
        return _mask_card(value)
    if pii_type == "AccountNumber":
        return _mask_account(value)
    if pii_type == "Email":
        return _mask_email(value)
    if pii_type == "PhoneNumber":
        return _mask_phone(value)
    return "[REDACTED]"


def fix_advice(pii_type: str) -> str:
    """Return a short, actionable recommendation for remediating the PII leak."""
    _advice = {
        "NRIC": (
            "Remove the hardcoded IC number. "
            "Store test identifiers in environment variables or a secrets vault, "
            "and use anonymised/synthetic values in test fixtures."
        ),
        "CreditCard": (
            "Tokenise or remove the card number. "
            "Never store raw card data in code or logs; "
            "use a payment vault (e.g. Stripe token, Braintree nonce) instead."
        ),
        "AccountNumber": (
            "Remove the hardcoded account number. "
            "Reference it via an environment variable or secrets manager, "
            "and replace test data with synthetic account numbers."
        ),
        "Email": (
            "Remove or redact the email address from code, logs, and test fixtures. "
            "Use placeholder addresses (e.g. test@example.com) in tests, "
            "and store real addresses in a secrets manager or environment variable."
        ),
        "PhoneNumber": (
            "Remove or redact the phone number from code, logs, and test fixtures. "
            "Use placeholder numbers in tests, "
            "and store real numbers in a secrets manager or environment variable."
        ),
        "RiskyLog": (
            "This log call interpolates a variable that may contain PII. "
            "Wrap the logged object with a masking helper before logging, "
            "or log only safe scalar fields (e.g. customer.id, not customer). "
            "Consider a structured logging library with field-level redaction."
        ),
    }
    return _advice.get(
        pii_type,
        "Remove or redact the sensitive value and store it in a secrets manager.",
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _mask_nric(value: str) -> str:
    """Keep year (first 2 digits), mask everything else, preserve dashes."""
    has_dashes = "-" in value
    digits = value.replace("-", "")
    if len(digits) < 2:
        return "[REDACTED]"
    # Keep year (2 digits), mask the remaining 10
    masked_digits = digits[:2] + "*" * (len(digits) - 2)
    if has_dashes:
        # Reinsert dashes at positions 6 and 9 of the original format
        return f"{masked_digits[:6]}-{masked_digits[6:8]}-{masked_digits[8:]}"
    return masked_digits


def _mask_card(value: str) -> str:
    """Keep last 4 digits of the card number, mask the rest with '*'."""
    digits = [c for c in value if c.isdigit()]
    if len(digits) < 4:
        return "[REDACTED]"
    masked = "*" * (len(digits) - 4) + "".join(digits[-4:])
    return masked


def _mask_account(value: str) -> str:
    """Keep last 4 digits of the account number, mask the rest with '*'."""
    digits = value.strip()
    if len(digits) < 4:
        return "[REDACTED]"
    return "*" * (len(digits) - 4) + digits[-4:]


def _mask_email(value: str) -> str:
    """Mask the local part of an email, keep the domain.

    Example: john.doe@example.com -> ********@example.com
    """
    if "@" not in value:
        return "[REDACTED]"
    local, domain = value.rsplit("@", 1)
    return "*" * len(local) + "@" + domain


def _mask_phone(value: str) -> str:
    """Keep the last 4 digits of a phone number, mask all other digits.

    Example: +60123456789 -> +******6789
             012-3456789  -> ***-***6789
    """
    digits = [c for c in value if c.isdigit()]
    if len(digits) < 4:
        return "[REDACTED]"
    # Rebuild the original string, replacing all digits except the last 4 with *
    keep = digits[-4:]
    keep_idx = len(digits) - 4  # number of digits to mask
    result = []
    masked_count = 0
    for ch in value:
        if ch.isdigit():
            if masked_count < keep_idx:
                result.append("*")
                masked_count += 1
            else:
                result.append(ch)
        else:
            result.append(ch)
    return "".join(result)
