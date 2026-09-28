"""TDD: Tests for generate_fix_line — paste-ready corrected source lines."""
import pytest
from pii_scanner.masker import generate_fix_line


class TestGenerateFixLine:
    def test_replaces_nric_in_context(self):
        context = "test_ic = '900101-01-1234'"
        result = generate_fix_line(context, "900101-01-1234", "90****-**-****")
        assert "90****-**-****" in result
        assert "900101-01-1234" not in result

    def test_replaces_credit_card_in_context(self):
        context = 'card = "4532015112830366"'
        result = generate_fix_line(context, "4532015112830366", "************0366")
        assert "************0366" in result
        assert "4532015112830366" not in result

    def test_replaces_email_in_context(self):
        context = 'email = "admin@company.com"'
        result = generate_fix_line(context, "admin@company.com", "*****@company.com")
        assert "*****@company.com" in result
        assert "admin@company.com" not in result

    def test_replaces_phone_in_context(self):
        context = "PHONE=+60123456789"
        result = generate_fix_line(context, "+60123456789", "+*******6789")
        assert "+*******6789" in result
        assert "+60123456789" not in result

    def test_preserves_surrounding_code(self):
        context = "logger.info(f'IC: {900101-01-1234}')"
        result = generate_fix_line(context, "900101-01-1234", "90****-**-****")
        assert "logger.info" in result
        assert "90****-**-****" in result

    def test_replaces_multiple_occurrences(self):
        context = "assert ic == '900101-01-1234' or ic == '900101-01-1234'"
        result = generate_fix_line(context, "900101-01-1234", "90****-**-****")
        assert "900101-01-1234" not in result
        assert result.count("90****-**-****") == 2

    def test_value_not_in_context_returns_context_unchanged(self):
        context = "x = 42"
        result = generate_fix_line(context, "900101-01-1234", "90****-**-****")
        assert result == context

    def test_empty_context_returns_empty(self):
        result = generate_fix_line("", "900101-01-1234", "90****-**-****")
        assert result == ""
