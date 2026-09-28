"""TDD: Tests for Email and PhoneNumber detection in scanner."""
import pytest
from pii_scanner.scanner import scan_line, scan_file, scan_directory


class TestScanLineEmail:
    def test_detects_email(self):
        results = scan_line("contact: john@example.com", 1, "app.py")
        hits = [r for r in results if r["type"] == "Email"]
        assert len(hits) == 1
        assert hits[0]["value"] == "john@example.com"

    def test_email_result_has_masked_value(self):
        results = scan_line("email=alice@corp.net", 1, "config.py")
        hit = next(r for r in results if r["type"] == "Email")
        assert "masked_value" in hit
        assert "@corp.net" in hit["masked_value"]

    def test_email_result_has_fix(self):
        results = scan_line("user@test.com", 1, "seed.py")
        hit = next(r for r in results if r["type"] == "Email")
        assert isinstance(hit["fix"], str) and len(hit["fix"]) > 0

    def test_email_result_has_correct_metadata(self):
        results = scan_line("send to: bob@mail.io", 7, "src/notify.py")
        hit = next(r for r in results if r["type"] == "Email")
        assert hit["file"] == "src/notify.py"
        assert hit["line"] == 7

    def test_no_email_on_clean_line(self):
        results = scan_line("no sensitive data here", 1, "readme.txt")
        assert not any(r["type"] == "Email" for r in results)

    def test_multiple_emails_on_same_line(self):
        results = scan_line("from: a@x.com to: b@y.com", 1, "mail.log")
        hits = [r for r in results if r["type"] == "Email"]
        assert len(hits) == 2

    def test_email_and_phone_on_same_line(self):
        results = scan_line("email=a@b.com phone=0123456789", 1, "user.csv")
        types = {r["type"] for r in results}
        assert "Email" in types
        assert "PhoneNumber" in types


class TestScanLinePhone:
    def test_detects_malaysian_mobile(self):
        results = scan_line("mobile: 012-3456789", 1, "app.py")
        hits = [r for r in results if r["type"] == "PhoneNumber"]
        assert len(hits) == 1

    def test_detects_phone_with_country_code(self):
        results = scan_line("phone: +60123456789", 1, "config.env")
        hits = [r for r in results if r["type"] == "PhoneNumber"]
        assert len(hits) == 1

    def test_phone_result_has_masked_value(self):
        results = scan_line("tel: 0123456789", 1, "data.csv")
        hit = next(r for r in results if r["type"] == "PhoneNumber")
        assert "masked_value" in hit
        assert hit["masked_value"].endswith("6789")

    def test_phone_result_has_fix(self):
        results = scan_line("tel: 0123456789", 1, "data.csv")
        hit = next(r for r in results if r["type"] == "PhoneNumber")
        assert isinstance(hit["fix"], str) and len(hit["fix"]) > 0

    def test_no_phone_on_clean_line(self):
        results = scan_line("hello world", 1, "readme.txt")
        assert not any(r["type"] == "PhoneNumber" for r in results)


class TestScanFileEmailPhone:
    def test_scan_file_finds_email(self, tmp_path):
        f = tmp_path / "data.py"
        f.write_text('email = "admin@example.com"\n')
        results = scan_file(str(f))
        assert any(r["type"] == "Email" for r in results)

    def test_scan_file_finds_phone(self, tmp_path):
        f = tmp_path / "config.env"
        f.write_text("SUPPORT_PHONE=+60123456789\n")
        results = scan_file(str(f))
        assert any(r["type"] == "PhoneNumber" for r in results)

    def test_scan_directory_finds_email_in_subdir(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "seed.csv").write_text("id,email\n1,test@company.com\n")
        results = scan_directory(str(tmp_path))
        assert any(r["type"] == "Email" for r in results)
