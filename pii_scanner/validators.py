"""Validators for confirming PII matches are genuine."""


def luhn_check(number: str) -> bool:
    """Validate a credit card number using the Luhn algorithm.

    Accepts digits with optional spaces or dashes (e.g. '4532 0151 1283 0366').
    Returns True if the number passes the Luhn check.
    """
    digits = [int(d) for d in number if d.isdigit()]
    if not digits:
        return False
    digits.reverse()
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def is_valid_nric(value: str) -> bool:
    """Validate a Malaysian NRIC (MyKad) number.

    Accepts formats with or without dashes: '900101-01-1234' or '900101011234'.
    Checks:
      - Total of 12 digits
      - Month between 01 and 12
      - Day between 01 and 31
      - State code >= 01
    """
    digits = value.replace("-", "")
    if len(digits) != 12:
        return False
    try:
        month = int(digits[2:4])
        day = int(digits[4:6])
        state = int(digits[6:8])
    except ValueError:
        return False
    return (1 <= month <= 12) and (1 <= day <= 31) and (state >= 1)
