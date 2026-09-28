"""TDD: Tests for validators — Luhn check and NRIC validation."""
import pytest
from pii_scanner.validators import luhn_check, is_valid_nric


class TestLuhnCheck:
    def test_valid_visa(self):
        assert luhn_check("4532015112830366") is True

    def test_valid_mastercard(self):
        assert luhn_check("5425233430109903") is True

    def test_valid_amex(self):
        # Standard Amex test number from payment processor docs
        assert luhn_check("378282246310005") is True

    def test_invalid_number(self):
        assert luhn_check("1234567890123456") is False

    def test_single_digit_zero(self):
        assert luhn_check("0") is True

    def test_strips_spaces(self):
        # Luhn operates on digits only; spaces should be ignored
        assert luhn_check("4532 0151 1283 0366") is True

    def test_strips_dashes(self):
        assert luhn_check("4532-0151-1283-0366") is True

    def test_all_zeros_except_valid(self):
        # All-zeros actually passes Luhn (sum=0, divisible by 10); confirm the
        # implementation agrees with the mathematical truth rather than a myth.
        assert luhn_check("0000000000000000") is True


class TestIsValidNric:
    def test_valid_nric_with_dashes(self):
        # Born Jan 1, 1990, state 01
        assert is_valid_nric("900101-01-1234") is True

    def test_valid_nric_without_dashes(self):
        assert is_valid_nric("900101011234") is True

    def test_invalid_month_00(self):
        assert is_valid_nric("900001-01-1234") is False

    def test_invalid_month_13(self):
        assert is_valid_nric("901301-01-1234") is False

    def test_invalid_day_00(self):
        assert is_valid_nric("900100-01-1234") is False

    def test_invalid_day_32(self):
        assert is_valid_nric("900132-01-1234") is False

    def test_invalid_state_00(self):
        assert is_valid_nric("900101-00-1234") is False

    def test_wrong_length_short(self):
        assert is_valid_nric("90010101123") is False

    def test_wrong_length_long(self):
        assert is_valid_nric("9001010112345") is False
