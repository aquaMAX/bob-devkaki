"""Customer service layer.

This module is a SAMPLE TARGET for the PII leak detection scanner.
It contains FOUR deliberately planted leaks of varying subtlety:

  LEAK 1 — Obvious (line 44):
      A raw NRIC is hardcoded into a log message as a literal string.
      Easy to spot in code review.

  LEAK 2 — Indirect / object logging (line 63):
      The entire Customer object is interpolated into an f-string log call.
      Customer.__repr__ includes ic_number, email, phone, and account_number.
      This leak is invisible in the source — no PII literal appears here —
      but the scanner flags it as a RiskyLog pattern.

  LEAK 3 — Exception message (line 88):
      A caught exception is logged directly. The exception was constructed
      with a full request payload dict that includes the credit card number.
      Again no PII literal in this file, but the log call is a leak vector.

  LEAK 4 — Subtle / config seed value (line 110):
      A default fallback email is hardcoded as a module-level constant and
      used in a notification path. Looks like a config value, not PII,
      but it is a real address that would appear in logs and test output.
"""

import logging

from .customer_model import Customer, CUSTOMERS

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. get_customer
# ---------------------------------------------------------------------------

def get_customer(customer_id: str) -> Customer:
    """Fetch a customer by ID.

    LEAK 1 — Obvious literal IC in log message.
    A developer added this debug line while investigating a bug and forgot
    to remove it. The NRIC appears verbatim in every log aggregator.
    """
    logger.debug("Fetching customer, last known IC was 900101-01-1234")   # ← LEAK 1
    customer = CUSTOMERS.get(customer_id)
    if customer is None:
        raise KeyError(f"Customer {customer_id} not found")
    return customer


# ---------------------------------------------------------------------------
# 2. process_transaction
# ---------------------------------------------------------------------------

def process_transaction(customer_id: str, amount: float) -> dict:
    """Process a debit transaction for a customer.

    LEAK 2 — Whole Customer object logged via f-string interpolation.
    Customer.__repr__ emits ic_number, email, phone, and account_number.
    No PII literal exists in this line — the leak only materialises at
    runtime when __repr__ is evaluated by the logger.
    """
    customer = get_customer(customer_id)
    logger.info(f"Processing transaction for {customer}")                  # ← LEAK 2
    if amount <= 0:
        raise ValueError("Transaction amount must be positive")
    return {
        "customer_id": customer_id,
        "amount": amount,
        "status": "approved",
    }


# ---------------------------------------------------------------------------
# 3. update_credit_card
# ---------------------------------------------------------------------------

def update_credit_card(customer_id: str, new_card: str) -> bool:
    """Update the stored credit card number for a customer.

    LEAK 3 — Exception logged with full request payload.
    If validation fails the except block logs the raw exception, which
    was constructed with the entire request dict including the PAN.
    The scanner flags the log.error(f"...{e}...") call as a RiskyLog.
    """
    customer = get_customer(customer_id)
    try:
        if len(new_card.replace(" ", "").replace("-", "")) != 16:
            raise ValueError(
                f"Invalid card for request: {{'customer_id': '{customer_id}', 'card': '{new_card}'}}"
            )
        customer.credit_card = new_card
        return True
    except ValueError as e:
        logger.error(f"Card update failed: {e}")                          # ← LEAK 3
        return False


# ---------------------------------------------------------------------------
# 4. send_notification
# ---------------------------------------------------------------------------

# LEAK 4 — Real email address hardcoded as a fallback constant.
# Looks like an innocent config default, but it is a real address that
# will appear in logs, test output, and the codebase scan.
DEFAULT_NOTIFICATION_EMAIL = "ops-support@internalbank.com.my"            # ← LEAK 4


def send_notification(customer_id: str, message: str) -> dict:
    """Send an email notification to the customer (or fallback address)."""
    try:
        customer = get_customer(customer_id)
        recipient = customer.email
    except KeyError:
        recipient = DEFAULT_NOTIFICATION_EMAIL
    logger.info(f"Sending notification to {recipient}: {message}")
    return {"recipient": recipient, "message": message, "sent": True}


# ---------------------------------------------------------------------------
# 5. get_account_summary
# ---------------------------------------------------------------------------

def get_account_summary(customer_id: str) -> dict:
    """Return a safe summary of the customer account.

    This function is intentionally CLEAN — it does not leak PII.
    The scanner should find no issues here, demonstrating that clean
    code passes without false positives.
    """
    customer = get_customer(customer_id)
    return {
        "customer_id": customer.customer_id,
        "name": customer.name,
        "account_suffix": customer.account_number[-4:],   # last 4 only — safe
        "has_credit_card": customer.credit_card is not None,
    }
