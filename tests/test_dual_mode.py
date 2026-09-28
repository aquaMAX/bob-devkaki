"""TDD: Tests for --log flag, dual-mode scan, and split report sections."""
import json
import pytest
from pathlib import Path
from pii_scanner.scanner import scan_file, scan_directory
from pii_scanner.reporter import print_report, save_json_report


# ---------------------------------------------------------------------------
# Dual-mode scan: source findings vs log findings are distinguished by origin
# ---------------------------------------------------------------------------

class TestFindingOriginField:
    def test_source_scan_findings_have_origin_source(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text("ic = '900101-01-1234'\n")
        results = scan_file(str(f), origin="source")
        assert results[0]["origin"] == "source"

    def test_log_scan_findings_have_origin_log(self, tmp_path):
        f = tmp_path / "app.log"
        f.write_text("card: 4532015112830366\n")
        results = scan_file(str(f), origin="log")
        assert results[0]["origin"] == "log"

    def test_default_origin_is_source(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text("ic = '900101-01-1234'\n")
        results = scan_file(str(f))
        assert results[0]["origin"] == "source"

    def test_scan_directory_passes_origin(self, tmp_path):
        (tmp_path / "data.py").write_text("ic = '900101-01-1234'\n")
        results = scan_directory(str(tmp_path), origin="source")
        assert results[0]["origin"] == "source"


class TestDualModeReport:
    SOURCE_FINDING = {
        "type": "NRIC",
        "value": "900101-01-1234",
        "masked_value": "90****-**-****",
        "fix": "Remove hardcoded IC.",
        "fix_line": "ic = '90****-**-****'",
        "file": "src/app.py",
        "line": 5,
        "context": "ic = '900101-01-1234'",
        "origin": "source",
    }
    LOG_FINDING = {
        "type": "CreditCard",
        "value": "4532015112830366",
        "masked_value": "************0366",
        "fix": "Tokenise card number.",
        "fix_line": "card = '************0366'",
        "file": "tests/app.log",
        "line": 12,
        "context": "card: 4532015112830366",
        "origin": "log",
    }

    def test_report_shows_source_leaks_section(self, capsys):
        print_report([self.SOURCE_FINDING, self.LOG_FINDING])
        out = capsys.readouterr().out
        assert "SOURCE" in out.upper() or "source" in out.lower()

    def test_report_shows_log_leaks_section(self, capsys):
        print_report([self.SOURCE_FINDING, self.LOG_FINDING])
        out = capsys.readouterr().out
        assert "LOG" in out.upper() or "log" in out.lower()

    def test_report_shows_fix_line(self, capsys):
        print_report([self.SOURCE_FINDING])
        out = capsys.readouterr().out
        assert "90****-**-****" in out

    def test_json_report_contains_origin(self, tmp_path):
        out = tmp_path / "report.json"
        save_json_report([self.SOURCE_FINDING, self.LOG_FINDING], str(out))
        data = json.loads(out.read_text())
        origins = {d["origin"] for d in data}
        assert "source" in origins
        assert "log" in origins

    def test_json_report_contains_fix_line(self, tmp_path):
        out = tmp_path / "report.json"
        save_json_report([self.SOURCE_FINDING], str(out))
        data = json.loads(out.read_text())
        assert "fix_line" in data[0]
        assert "90****-**-****" in data[0]["fix_line"]

    def test_only_log_findings_no_source_section_header_needed(self, capsys):
        print_report([self.LOG_FINDING])
        out = capsys.readouterr().out
        assert "4532015112830366" in out

    def test_no_findings_still_prints_clean(self, capsys):
        print_report([])
        out = capsys.readouterr().out
        assert "No PII" in out
