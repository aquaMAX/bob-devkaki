"""Tests for customer_service.py.

Running these tests with logging enabled produces a log file (sample.log)
that contains the runtime PII leaks triggered by LEAK 2 and LEAK 3.
The pii-scanner can then be pointed at that log file with --log to
demonstrate dual-mode detection.

Run:
    pytest sample/tests/ -s --log-file=sample/sample.log --log-file-level=DEBUG
"""

import logging
import pytest

# Make sample package importable when run from project root
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sample.customer_service import (
    get_customer,
    process_transaction,
    update_credit_card,
    send_notification,
    get_account_summary,
)
from sample.customer_model import Customer


# ---------------------------------------------------------------------------
# get_customer
# ---------------------------------------------------------------------------

class TestGetCustomer:
    def test_returns_customer_for_valid_id(self):
        customer = get_customer("C001")
        assert isinstance(customer, Customer)
        assert customer.customer_id == "C001"

    def test_returns_correct_name(self):
        customer = get_customer("C001")
        assert customer.name == "Ahmad Bin Abdullah"

    def test_raises_key_error_for_unknown_id(self):
        with pytest.raises(KeyError):
            get_customer("UNKNOWN")


# ---------------------------------------------------------------------------
# process_transaction
# ---------------------------------------------------------------------------

class TestProcessTransaction:
    def test_approved_for_valid_amount(self):
        result = process_transaction("C001", 100.00)
        assert result["status"] == "approved"

    def test_returns_correct_customer_id(self):
        result = process_transaction("C001", 50.00)
        assert result["customer_id"] == "C001"

    def test_raises_for_zero_amount(self):
        with pytest.raises(ValueError, match="positive"):
            process_transaction("C001", 0)

    def test_raises_for_negative_amount(self):
        with pytest.raises(ValueError):
            process_transaction("C001", -10.00)

    def test_raises_for_unknown_customer(self):
        with pytest.raises(KeyError):
            process_transaction("GHOST", 10.00)


# ---------------------------------------------------------------------------
# update_credit_card
# ---------------------------------------------------------------------------

class TestUpdateCreditCard:
    def test_valid_card_returns_true(self):
        # 16-digit test card number
        result = update_credit_card("C001", "5425233430109903")
        assert result is True

    def test_short_card_returns_false(self):
        result = update_credit_card("C001", "1234")
        assert result is False

    def test_card_with_spaces_accepted(self):
        result = update_credit_card("C001", "5425 2334 3010 9903")
        assert result is True

    def test_card_with_dashes_accepted(self):
        result = update_credit_card("C001", "5425-2334-3010-9903")
        assert result is True


# ---------------------------------------------------------------------------
# send_notification
# ---------------------------------------------------------------------------

class TestSendNotification:
    def test_sends_to_customer_email(self):
        result = send_notification("C001", "Your statement is ready.")
        assert result["recipient"] == "ahmad@example.com"
        assert result["sent"] is True

    def test_falls_back_to_default_email_for_unknown_customer(self):
        result = send_notification("GHOST", "Hello")
        assert "@" in result["recipient"]   # some fallback address
        assert result["sent"] is True

    def test_message_preserved_in_result(self):
        msg = "Transaction approved."
        result = send_notification("C002", msg)
        assert result["message"] == msg


# ---------------------------------------------------------------------------
# get_account_summary
# ---------------------------------------------------------------------------

class TestGetAccountSummary:
    def test_returns_last_four_of_account(self):
        summary = get_account_summary("C001")
        assert summary["account_suffix"] == "1234"

    def test_does_not_expose_full_account_number(self):
        summary = get_account_summary("C001")
        assert "account_number" not in summary
        assert len(summary["account_suffix"]) == 4

    def test_does_not_expose_ic_number(self):
        summary = get_account_summary("C001")
        assert "ic_number" not in summary
        assert "900101" not in str(summary)

    def test_does_not_expose_credit_card(self):
        summary = get_account_summary("C001")
        assert "credit_card" not in summary
        # has_credit_card is a boolean flag only
        assert isinstance(summary["has_credit_card"], bool)

    def test_has_credit_card_true_for_c001(self):
        summary = get_account_summary("C001")
        assert summary["has_credit_card"] is True

    def test_has_credit_card_false_for_c002(self):
        summary = get_account_summary("C002")
        assert summary["has_credit_card"] is False

    def test_raises_for_unknown_customer(self):
        with pytest.raises(KeyError):
            get_account_summary("UNKNOWN")
