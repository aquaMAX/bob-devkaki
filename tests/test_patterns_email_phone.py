"""TDD: Tests for Email and PhoneNumber regex patterns."""
import pytest
from pii_scanner.patterns import EMAIL_PATTERN, PHONE_PATTERN


class TestEmailPattern:
    def test_matches_simple_email(self):
        assert EMAIL_PATTERN.search("user@example.com") is not None

    def test_matches_email_in_sentence(self):
        assert EMAIL_PATTERN.search("contact: john.doe@company.org") is not None

    def test_matches_email_with_plus(self):
        assert EMAIL_PATTERN.search("user+tag@mail.io") is not None

    def test_matches_email_with_subdomain(self):
        assert EMAIL_PATTERN.search("admin@sub.domain.com") is not None

    def test_matches_email_with_dots_in_local(self):
        assert EMAIL_PATTERN.search("first.last@example.co.uk") is not None

    def test_matches_email_with_numbers(self):
        assert EMAIL_PATTERN.search("user123@test456.com") is not None

    def test_no_match_missing_at(self):
        assert EMAIL_PATTERN.search("userexample.com") is None

    def test_no_match_missing_domain(self):
        assert EMAIL_PATTERN.search("user@") is None

    def test_no_match_missing_tld(self):
        assert EMAIL_PATTERN.search("user@domain") is None

    def test_no_match_plain_word(self):
        assert EMAIL_PATTERN.search("hello world") is None

    def test_captures_full_email(self):
        m = EMAIL_PATTERN.search("email=john@example.com")
        assert m.group(0) == "john@example.com"

    def test_matches_email_in_json(self):
        assert EMAIL_PATTERN.search('{"email": "alice@corp.net"}') is not None


class TestPhonePattern:
    def test_matches_my_local_format(self):
        # Malaysian mobile: 01X-XXXXXXX
        assert PHONE_PATTERN.search("012-3456789") is not None

    def test_matches_my_with_country_code(self):
        assert PHONE_PATTERN.search("+60123456789") is not None

    def test_matches_my_country_code_spaced(self):
        assert PHONE_PATTERN.search("+601 2345 6789") is not None

    def test_matches_generic_10_digit(self):
        assert PHONE_PATTERN.search("0123456789") is not None

    def test_matches_with_parentheses(self):
        assert PHONE_PATTERN.search("(012) 345-6789") is not None

    def test_matches_intl_format_plus_country(self):
        assert PHONE_PATTERN.search("+1-800-555-0199") is not None

    def test_no_match_too_short(self):
        # 6 digits — not a phone number
        assert PHONE_PATTERN.search("123456") is None

    def test_no_match_plain_text(self):
        assert PHONE_PATTERN.search("hello world") is None

    def test_matches_phone_in_sentence(self):
        assert PHONE_PATTERN.search("call me at 012-9876543 tomorrow") is not None

    def test_matches_phone_in_json(self):
        assert PHONE_PATTERN.search('{"phone": "+60123456789"}') is not None
