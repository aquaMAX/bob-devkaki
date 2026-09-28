"""TDD: Tests for masker — per-type PII masking and fix advice."""
import pytest
from pii_scanner.masker import mask_value, fix_advice


class TestMaskValue:
    # --- NRIC ---
    def test_nric_masks_middle_digits(self):
        # Format: YYMMDD-SS-NNNN  → YY****-**-****
        result = mask_value("NRIC", "900101-01-1234")
        assert result.startswith("90")
        assert "****" in result
        assert "900101-01-1234" not in result

    def test_nric_without_dashes_masked(self):
        result = mask_value("NRIC", "900101011234")
        assert result.startswith("90")
        assert "****" in result

    # --- CreditCard ---
    def test_credit_card_shows_last_four(self):
        # Standard masking: only last 4 digits visible
        result = mask_value("CreditCard", "4532015112830366")
        assert result.endswith("0366")
        assert "4532015112830366" not in result

    def test_credit_card_masked_chars_are_stars(self):
        result = mask_value("CreditCard", "4532015112830366")
        # All non-last-4 digit positions should be masked
        assert "*" in result

    def test_credit_card_spaced_shows_last_four(self):
        result = mask_value("CreditCard", "4532 0151 1283 0366")
        assert "0366" in result
        assert "4532" not in result

    # --- AccountNumber ---
    def test_account_number_shows_last_four(self):
        result = mask_value("AccountNumber", "1234567890")
        assert result.endswith("7890")
        assert "123456" not in result

    def test_account_number_masked_chars_are_stars(self):
        result = mask_value("AccountNumber", "1234567890")
        assert "*" in result

    # --- Unknown type ---
    def test_unknown_type_fully_masked(self):
        result = mask_value("Unknown", "sensitive_data")
        assert result == "[REDACTED]"


class TestFixAdvice:
    def test_nric_fix_advice_mentions_env_or_config(self):
        advice = fix_advice("NRIC")
        lower = advice.lower()
        assert any(word in lower for word in ("environment", "env", "config", "variable", "vault", "remove", "hardcoded"))

    def test_credit_card_fix_advice_mentions_tokenise_or_remove(self):
        advice = fix_advice("CreditCard")
        lower = advice.lower()
        assert any(word in lower for word in ("tokenis", "tokeniz", "remove", "vault", "secret", "mask"))

    def test_account_number_fix_advice_not_empty(self):
        advice = fix_advice("AccountNumber")
        assert isinstance(advice, str) and len(advice) > 0

    def test_unknown_type_returns_generic_advice(self):
        advice = fix_advice("Unknown")
        assert isinstance(advice, str) and len(advice) > 0
