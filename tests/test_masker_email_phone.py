"""TDD: Tests for Email and PhoneNumber masking and fix advice."""
import pytest
from pii_scanner.masker import mask_value, fix_advice


class TestMaskEmail:
    def test_masks_local_part(self):
        result = mask_value("Email", "john.doe@example.com")
        assert "@example.com" in result
        assert "john.doe" not in result

    def test_keeps_domain(self):
        result = mask_value("Email", "alice@corp.net")
        assert "@corp.net" in result

    def test_masked_local_contains_stars(self):
        result = mask_value("Email", "user@test.com")
        assert "*" in result

    def test_short_local_part_still_masked(self):
        result = mask_value("Email", "a@b.com")
        assert "@b.com" in result
        assert "a" not in result.split("@")[0]

    def test_unknown_email_format_returns_redacted(self):
        # No @ symbol — fallback
        result = mask_value("Email", "notanemail")
        assert result == "[REDACTED]"


class TestMaskPhone:
    def test_keeps_last_four_digits(self):
        result = mask_value("PhoneNumber", "0123456789")
        assert result.endswith("6789")

    def test_masks_non_last_four_digits(self):
        result = mask_value("PhoneNumber", "0123456789")
        assert "*" in result
        assert "012345" not in result

    def test_formatted_phone_last_four_preserved(self):
        result = mask_value("PhoneNumber", "+60123456789")
        assert result.endswith("6789")

    def test_short_phone_returns_redacted(self):
        result = mask_value("PhoneNumber", "123")
        assert result == "[REDACTED]"


class TestFixAdviceEmailPhone:
    def test_email_fix_advice_mentions_logging_or_env(self):
        advice = fix_advice("Email")
        lower = advice.lower()
        assert any(word in lower for word in ("log", "env", "remove", "redact", "mask", "store"))

    def test_phone_fix_advice_not_empty(self):
        advice = fix_advice("PhoneNumber")
        assert isinstance(advice, str) and len(advice) > 0

    def test_phone_fix_advice_mentions_removal_or_masking(self):
        advice = fix_advice("PhoneNumber")
        lower = advice.lower()
        assert any(word in lower for word in ("remove", "redact", "mask", "env", "vault", "store"))
