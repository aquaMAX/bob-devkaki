"""TDD: Tests for regex patterns."""
import pytest
from pii_scanner.patterns import NRIC_PATTERN, CREDIT_CARD_PATTERN, ACCOUNT_NUMBER_PATTERN


class TestNricPattern:
    def test_matches_with_dashes(self):
        assert NRIC_PATTERN.search("ID: 900101-01-1234") is not None

    def test_matches_without_dashes(self):
        assert NRIC_PATTERN.search("nric=900101011234") is not None

    def test_no_match_random_digits(self):
        # 6 digits only — too short
        assert NRIC_PATTERN.search("123456") is None

    def test_no_match_invalid_month_in_pattern(self):
        # Month 13 — pattern restricts to 01-12
        assert NRIC_PATTERN.search("901301-01-1234") is None

    def test_no_match_invalid_day_in_pattern(self):
        # Day 32 — pattern restricts to 01-31
        assert NRIC_PATTERN.search("900132-01-1234") is None

    def test_captures_correctly(self):
        m = NRIC_PATTERN.search("900101-01-1234")
        assert m is not None
        assert m.group(0) == "900101-01-1234"


class TestCreditCardPattern:
    def test_matches_visa(self):
        assert CREDIT_CARD_PATTERN.search("card: 4532015112830366") is not None

    def test_matches_mastercard(self):
        assert CREDIT_CARD_PATTERN.search("cc=5425233430109903") is not None

    def test_matches_amex(self):
        assert CREDIT_CARD_PATTERN.search("374251018720955") is not None

    def test_matches_spaced_card(self):
        assert CREDIT_CARD_PATTERN.search("4532 0151 1283 0366") is not None

    def test_matches_dashed_card(self):
        assert CREDIT_CARD_PATTERN.search("4532-0151-1283-0366") is not None

    def test_no_match_too_short(self):
        # 12 digits — too short for any card
        assert CREDIT_CARD_PATTERN.search("123456789012") is None


class TestAccountNumberPattern:
    def test_matches_10_digits(self):
        assert ACCOUNT_NUMBER_PATTERN.search("acc=1234567890") is not None

    def test_matches_16_digits(self):
        assert ACCOUNT_NUMBER_PATTERN.search("1234567890123456") is not None

    def test_no_match_9_digits(self):
        assert ACCOUNT_NUMBER_PATTERN.search("123456789") is None

    def test_no_match_17_digits(self):
        # 17 digits as a word boundary — should not match
        assert ACCOUNT_NUMBER_PATTERN.search("12345678901234567") is None
