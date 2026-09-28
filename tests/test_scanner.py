"""TDD: Tests for the core scanner — scan_line, scan_file, scan_directory."""
import os
import json
import pytest
import tempfile
from pathlib import Path
from pii_scanner.scanner import scan_line, scan_file, scan_directory


class TestScanLineMaskedFields:
    def test_finding_has_masked_value(self):
        results = scan_line("ic: 900101-01-1234", 1, "app.py")
        assert "masked_value" in results[0]

    def test_finding_has_fix_field(self):
        results = scan_line("ic: 900101-01-1234", 1, "app.py")
        assert "fix" in results[0]

    def test_nric_masked_value_differs_from_raw(self):
        results = scan_line("ic: 900101-01-1234", 1, "app.py")
        assert results[0]["masked_value"] != results[0]["value"]

    def test_credit_card_masked_shows_last_four(self):
        results = scan_line("cc: 4532015112830366", 1, "pay.py")
        cc = next(r for r in results if r["type"] == "CreditCard")
        assert cc["masked_value"].endswith("0366")

    def test_fix_is_non_empty_string(self):
        results = scan_line("account=1234567890", 1, "db.log")
        assert isinstance(results[0]["fix"], str)
        assert len(results[0]["fix"]) > 0


class TestScanLine:
    def test_detects_nric(self):
        results = scan_line("User IC: 900101-01-1234", 1, "test.py")
        nric_hits = [r for r in results if r["type"] == "NRIC"]
        assert len(nric_hits) == 1
        assert "900101-01-1234" in nric_hits[0]["value"]

    def test_detects_credit_card(self):
        results = scan_line("payment: 4532015112830366", 5, "payment.log")
        cc_hits = [r for r in results if r["type"] == "CreditCard"]
        assert len(cc_hits) == 1

    def test_credit_card_fails_luhn_not_reported(self):
        # 4532015112830367 — last digit changed, fails Luhn
        results = scan_line("cc: 4532015112830367", 1, "test.py")
        cc_hits = [r for r in results if r["type"] == "CreditCard"]
        assert len(cc_hits) == 0

    def test_detects_account_number(self):
        # 14 digits — too long for phone, unambiguously an account number
        results = scan_line("account=12345678901234", 3, "db.log")
        acc_hits = [r for r in results if r["type"] == "AccountNumber"]
        assert len(acc_hits) == 1
        assert acc_hits[0]["value"] == "12345678901234"

    def test_account_number_not_double_reported_when_matches_cc(self):
        # Valid Visa — should appear as CreditCard, NOT also as AccountNumber
        results = scan_line("4532015112830366", 1, "file.py")
        types = [r["type"] for r in results]
        assert "CreditCard" in types
        assert "AccountNumber" not in types

    def test_result_contains_metadata(self):
        results = scan_line("ic: 900101-01-1234", 10, "src/app.py")
        assert results[0]["file"] == "src/app.py"
        assert results[0]["line"] == 10
        assert "context" in results[0]

    def test_clean_line_returns_empty(self):
        results = scan_line("hello world, no pii here", 1, "readme.txt")
        assert results == []

    def test_multiple_pii_on_same_line(self):
        line = "ic=900101-01-1234 cc=4532015112830366"
        results = scan_line(line, 1, "leak.txt")
        types = {r["type"] for r in results}
        assert "NRIC" in types
        assert "CreditCard" in types


class TestScanFile:
    def test_scans_file_and_finds_nric(self, tmp_path):
        f = tmp_path / "data.txt"
        f.write_text("customer ic: 900101-01-1234\nname: John\n")
        results = scan_file(str(f))
        assert any(r["type"] == "NRIC" for r in results)

    def test_scans_file_clean(self, tmp_path):
        f = tmp_path / "clean.txt"
        f.write_text("nothing sensitive here\n")
        results = scan_file(str(f))
        assert results == []

    def test_handles_missing_file_gracefully(self):
        results = scan_file("/nonexistent/path/file.txt")
        assert results == []

    def test_line_numbers_are_correct(self, tmp_path):
        f = tmp_path / "lined.txt"
        f.write_text("line one\nline two\nic: 900101-01-1234\n")
        results = scan_file(str(f))
        assert results[0]["line"] == 3

    def test_skips_binary_gracefully(self, tmp_path):
        f = tmp_path / "binary.bin"
        f.write_bytes(bytes(range(256)))
        # Should not raise
        results = scan_file(str(f))
        assert isinstance(results, list)


class TestScanDirectory:
    def test_scans_py_files(self, tmp_path):
        (tmp_path / "app.py").write_text("ic = '900101-01-1234'\n")
        results = scan_directory(str(tmp_path))
        assert any(r["type"] == "NRIC" for r in results)

    def test_scans_log_files(self, tmp_path):
        (tmp_path / "out.log").write_text("card: 4532015112830366\n")
        results = scan_directory(str(tmp_path))
        assert any(r["type"] == "CreditCard" for r in results)

    def test_skips_unsupported_extension(self, tmp_path):
        (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n")
        (tmp_path / "clean.py").write_text("x = 1\n")
        results = scan_directory(str(tmp_path))
        assert results == []

    def test_recurses_subdirectories(self, tmp_path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        # 14 digits — unambiguously an account number, not a phone number
        (sub / "leak.txt").write_text("account=12345678901234\n")
        results = scan_directory(str(tmp_path))
        assert any(r["type"] == "AccountNumber" for r in results)

    def test_empty_directory_returns_empty(self, tmp_path):
        results = scan_directory(str(tmp_path))
        assert results == []
