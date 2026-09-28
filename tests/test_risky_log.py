"""TDD: Tests for RISKY_LOG_PATTERN — indirect leak detection via logging calls."""
import pytest
from pii_scanner.patterns import RISKY_LOG_PATTERN
from pii_scanner.scanner import scan_line


class TestRiskyLogPattern:
    def test_matches_logger_info_fstring(self):
        assert RISKY_LOG_PATTERN.search(
            'logger.info(f"Processing {customer}")'
        ) is not None

    def test_matches_logger_debug_fstring(self):
        assert RISKY_LOG_PATTERN.search(
            'logger.debug(f"Request: {request.__dict__}")'
        ) is not None

    def test_matches_log_error_fstring(self):
        assert RISKY_LOG_PATTERN.search(
            'log.error(f"Failed: {e}")'
        ) is not None

    def test_matches_logging_warning(self):
        assert RISKY_LOG_PATTERN.search(
            'logging.warning(f"User data: {user}")'
        ) is not None

    def test_matches_percent_format(self):
        assert RISKY_LOG_PATTERN.search(
            'logger.info("Processing %s", customer)'
        ) is not None

    def test_matches_str_format(self):
        assert RISKY_LOG_PATTERN.search(
            'logger.info("Data: {}".format(payload))'
        ) is not None

    def test_no_match_plain_log_string(self):
        # No variable interpolation — safe
        assert RISKY_LOG_PATTERN.search(
            'logger.info("Application started")'
        ) is None

    def test_no_match_non_log_call(self):
        assert RISKY_LOG_PATTERN.search(
            'print(f"Processing {customer}")'
        ) is None

    def test_no_match_log_with_safe_literal(self):
        assert RISKY_LOG_PATTERN.search(
            'logger.info("Processing customer 1234")'
        ) is None


class TestScanLineRiskyLog:
    def test_detects_risky_log_as_finding(self):
        results = scan_line(
            'logger.info(f"Processing {customer}")', 10, "src/service.py"
        )
        hits = [r for r in results if r["type"] == "RiskyLog"]
        assert len(hits) == 1

    def test_risky_log_finding_has_correct_type(self):
        results = scan_line(
            'log.error(f"Failed: {e}")', 5, "src/handler.py"
        )
        hit = next(r for r in results if r["type"] == "RiskyLog")
        assert hit["type"] == "RiskyLog"

    def test_risky_log_finding_has_file_and_line(self):
        results = scan_line(
            'logger.debug(f"User: {user_obj}")', 22, "app/views.py"
        )
        hit = next(r for r in results if r["type"] == "RiskyLog")
        assert hit["file"] == "app/views.py"
        assert hit["line"] == 22

    def test_risky_log_finding_has_fix(self):
        results = scan_line(
            'logger.info(f"Data: {payload}")', 1, "api.py"
        )
        hit = next(r for r in results if r["type"] == "RiskyLog")
        assert isinstance(hit["fix"], str) and len(hit["fix"]) > 0

    def test_risky_log_masked_value_is_warning(self):
        results = scan_line(
            'logger.info(f"Processing {customer}")', 1, "svc.py"
        )
        hit = next(r for r in results if r["type"] == "RiskyLog")
        assert "[INDIRECT LEAK RISK]" in hit["masked_value"]

    def test_risky_log_does_not_suppress_pii_on_same_line(self):
        # A log call that also contains a literal NRIC — both should fire
        line = 'logger.info(f"IC is {customer} 900101-01-1234")'
        results = scan_line(line, 1, "svc.py")
        types = {r["type"] for r in results}
        assert "RiskyLog" in types
        assert "NRIC" in types

    def test_safe_log_line_not_flagged(self):
        results = scan_line('logger.info("Server started on port 8080")', 1, "app.py")
        assert not any(r["type"] == "RiskyLog" for r in results)
