"""TDD: Tests for reporter — console output and JSON file output."""
import json
import pytest
from io import StringIO
from unittest.mock import patch, mock_open
from pii_scanner.reporter import print_report, save_json_report


SAMPLE_FINDINGS = [
    {
        "type": "NRIC",
        "value": "900101-01-1234",
        "masked_value": "90****-**-****",
        "fix": "Remove hardcoded IC number. Store test identifiers in environment variables or a secrets vault.",
        "file": "src/app.py",
        "line": 5,
        "context": "ic = '900101-01-1234'"
    },
    {
        "type": "CreditCard",
        "value": "4532015112830366",
        "masked_value": "************0366",
        "fix": "Tokenise or remove the card number. Never store raw card data; use a payment vault (e.g. Stripe token).",
        "file": "tests/test_payment.py",
        "line": 12,
        "context": "cc = '4532015112830366'"
    },
]


class TestPrintReport:
    def test_prints_no_findings_message(self, capsys):
        print_report([])
        captured = capsys.readouterr()
        assert "No PII" in captured.out

    def test_prints_finding_count(self, capsys):
        print_report(SAMPLE_FINDINGS)
        captured = capsys.readouterr()
        assert "2" in captured.out

    def test_prints_nric_type(self, capsys):
        print_report(SAMPLE_FINDINGS)
        captured = capsys.readouterr()
        assert "NRIC" in captured.out

    def test_prints_credit_card_type(self, capsys):
        print_report(SAMPLE_FINDINGS)
        captured = capsys.readouterr()
        assert "CreditCard" in captured.out

    def test_prints_file_and_line(self, capsys):
        print_report(SAMPLE_FINDINGS)
        captured = capsys.readouterr()
        assert "src/app.py" in captured.out
        assert ":5" in captured.out

    def test_prints_context(self, capsys):
        print_report(SAMPLE_FINDINGS)
        captured = capsys.readouterr()
        assert "900101-01-1234" in captured.out

    def test_prints_masked_value(self, capsys):
        print_report(SAMPLE_FINDINGS)
        captured = capsys.readouterr()
        assert "90****-**-****" in captured.out

    def test_prints_fix_advice(self, capsys):
        print_report(SAMPLE_FINDINGS)
        captured = capsys.readouterr()
        assert "fix" in captured.out.lower() or "remove" in captured.out.lower() or "token" in captured.out.lower()

    def test_masked_value_label_present(self, capsys):
        print_report(SAMPLE_FINDINGS)
        captured = capsys.readouterr()
        assert "Masked" in captured.out

    def test_trace_shows_file_colon_line(self, capsys):
        print_report(SAMPLE_FINDINGS)
        captured = capsys.readouterr()
        assert "src/app.py:5" in captured.out


class TestSaveJsonReport:
    def test_saves_valid_json(self, tmp_path):
        out = tmp_path / "report.json"
        save_json_report(SAMPLE_FINDINGS, str(out))
        data = json.loads(out.read_text())
        assert isinstance(data, list)
        assert len(data) == 2

    def test_json_contains_type_field(self, tmp_path):
        out = tmp_path / "report.json"
        save_json_report(SAMPLE_FINDINGS, str(out))
        data = json.loads(out.read_text())
        assert data[0]["type"] == "NRIC"

    def test_json_contains_all_fields(self, tmp_path):
        out = tmp_path / "report.json"
        save_json_report(SAMPLE_FINDINGS, str(out))
        data = json.loads(out.read_text())
        for field in ("type", "value", "masked_value", "fix", "file", "line", "context"):
            assert field in data[0]

    def test_empty_findings_saves_empty_list(self, tmp_path):
        out = tmp_path / "empty.json"
        save_json_report([], str(out))
        data = json.loads(out.read_text())
        assert data == []
