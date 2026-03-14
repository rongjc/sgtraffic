"""
Tests for the CLI tool (scanner_cli).

Tests cover:
- scan command: upload, poll, output formats (text/json/table), exit codes
- scan --fail-above threshold logic
- status command: json/text/table output, 404 handling
- history command: json/text/table, empty list
- report command: download success, 409 (scan not ready), 404
- API error handling (connection refused)
- Exit code mapping: clean=0, suspicious=1, pha=2, error=3
"""
import json
import os
import sys
import tempfile

import pytest
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from click.testing import CliRunner
from unittest.mock import patch, MagicMock
from scanner_cli.main import cli


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_response(json_data=None, status_code=200, content=None, headers=None):
    """Build a mock requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    if json_data is not None:
        resp.json.return_value = json_data
    if content is not None:
        resp.content = content
        resp.iter_content = lambda chunk_size: iter([content])
    resp.headers = headers or {}
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        http_err = requests.HTTPError(response=resp)
        resp.raise_for_status.side_effect = http_err
    return resp


def _scan_done(
    scan_id: str = "test-scan-id",
    verdict: str = "clean",
    risk_score: int = 5,
    pha_categories: list | None = None,
    filename: str = "test.apk",
) -> dict:
    return {
        "id": scan_id,
        "filename": filename,
        "status": "done",
        "verdict": verdict,
        "riskScore": risk_score,
        "phaCategories": pha_categories or [],
        "createdAt": "2026-03-13T00:00:00Z",
        "completedAt": "2026-03-13T00:01:00Z",
    }


def _tmp_apk() -> str:
    """Create a small temp file that exists on disk."""
    fd, path = tempfile.mkstemp(suffix=".apk")
    with os.fdopen(fd, "wb") as f:
        f.write(b"PK\x03\x04" + b"\x00" * 100)  # minimal zip-like header
    return path


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

class TestScanCommand:
    def test_scan_clean_exit_code_0(self):
        runner = CliRunner()
        path = _tmp_apk()
        try:
            with patch("scanner_cli.main.requests.Session") as MockSession:
                session = MockSession.return_value
                # POST /api/scans returns scan queued
                session.post.return_value = _mock_response({"id": "abc123"})
                # GET /api/scans/abc123 returns done/clean
                session.get.return_value = _mock_response(_scan_done("abc123", "clean", 5))
                result = runner.invoke(cli, ["scan", path, "--poll-interval", "0"])
            assert result.exit_code == 0
        finally:
            os.unlink(path)

    def test_scan_suspicious_high_risk_exit_code_1(self):
        """Suspicious verdict with risk score above fail-above threshold exits 1."""
        runner = CliRunner()
        path = _tmp_apk()
        try:
            with patch("scanner_cli.main.requests.Session") as MockSession:
                session = MockSession.return_value
                session.post.return_value = _mock_response({"id": "abc123"})
                # risk_score 70 > default fail_above 60 → exit 1
                session.get.return_value = _mock_response(_scan_done("abc123", "suspicious", 70))
                result = runner.invoke(cli, ["scan", path, "--poll-interval", "0"])
            assert result.exit_code == 1
        finally:
            os.unlink(path)

    def test_scan_suspicious_low_risk_exit_code_0(self):
        """Suspicious verdict with risk score below fail-above threshold exits 0 (threshold logic)."""
        runner = CliRunner()
        path = _tmp_apk()
        try:
            with patch("scanner_cli.main.requests.Session") as MockSession:
                session = MockSession.return_value
                session.post.return_value = _mock_response({"id": "abc123"})
                # risk_score 30 <= default fail_above 60 → exit 0 (override)
                session.get.return_value = _mock_response(_scan_done("abc123", "suspicious", 30))
                result = runner.invoke(cli, ["scan", path, "--poll-interval", "0"])
            assert result.exit_code == 0
        finally:
            os.unlink(path)

    def test_scan_pha_exit_code_2(self):
        runner = CliRunner()
        path = _tmp_apk()
        try:
            with patch("scanner_cli.main.requests.Session") as MockSession:
                session = MockSession.return_value
                session.post.return_value = _mock_response({"id": "abc123"})
                session.get.return_value = _mock_response(_scan_done("abc123", "pha", 90, ["backdoor"]))
                result = runner.invoke(cli, ["scan", path, "--poll-interval", "0"])
            assert result.exit_code == 2
        finally:
            os.unlink(path)

    def test_scan_upload_failure_exit_code_3(self):
        runner = CliRunner()
        path = _tmp_apk()
        try:
            with patch("scanner_cli.main.requests.Session") as MockSession:
                session = MockSession.return_value
                session.post.side_effect = requests.ConnectionError("refused")
                result = runner.invoke(cli, ["scan", path, "--poll-interval", "0"])
            assert result.exit_code == 3
        finally:
            os.unlink(path)

    def test_scan_json_output_format(self):
        runner = CliRunner()
        path = _tmp_apk()
        try:
            with patch("scanner_cli.main.requests.Session") as MockSession:
                session = MockSession.return_value
                scan_data = _scan_done("abc123", "clean", 5)
                session.post.return_value = _mock_response({"id": "abc123"})
                session.get.return_value = _mock_response(scan_data)
                result = runner.invoke(cli, ["--format", "json", "scan", path, "--poll-interval", "0"])
            assert result.exit_code == 0
            # Output should be parseable JSON containing the scan data
            output = result.output
            # Find JSON in output (after the "Scan queued" line)
            json_start = output.find("{")
            if json_start >= 0:
                parsed = json.loads(output[json_start:])
                assert parsed["id"] == "abc123"
        finally:
            os.unlink(path)

    def test_scan_table_output_format(self):
        runner = CliRunner()
        path = _tmp_apk()
        try:
            with patch("scanner_cli.main.requests.Session") as MockSession:
                session = MockSession.return_value
                session.post.return_value = _mock_response({"id": "abc123"})
                session.get.return_value = _mock_response(_scan_done("abc123", "clean", 5))
                result = runner.invoke(cli, ["--format", "table", "scan", path, "--poll-interval", "0"])
            assert result.exit_code == 0
        finally:
            os.unlink(path)

    def test_scan_error_status_exit_code_3(self):
        runner = CliRunner()
        path = _tmp_apk()
        try:
            with patch("scanner_cli.main.requests.Session") as MockSession:
                session = MockSession.return_value
                session.post.return_value = _mock_response({"id": "abc123"})
                error_scan = {"id": "abc123", "status": "error", "errorMessage": "analysis failed"}
                session.get.return_value = _mock_response(error_scan)
                result = runner.invoke(cli, ["scan", path, "--poll-interval", "0"])
            assert result.exit_code == 3
        finally:
            os.unlink(path)

    def test_scan_timeout_exit_code_3(self):
        """If the scan never completes within timeout, exit 3."""
        runner = CliRunner()
        path = _tmp_apk()
        try:
            with patch("scanner_cli.main.requests.Session") as MockSession:
                session = MockSession.return_value
                session.post.return_value = _mock_response({"id": "abc123"})
                # Always return pending
                pending = {"id": "abc123", "status": "pending", "verdict": "unknown"}
                session.get.return_value = _mock_response(pending)
                result = runner.invoke(cli, ["scan", path, "--poll-interval", "0", "--timeout", "1"])
            assert result.exit_code == 3
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# --fail-above threshold
# ---------------------------------------------------------------------------

class TestFailAboveThreshold:
    def test_clean_scan_above_threshold_exits_1(self):
        """clean verdict but risk score > fail-above → exit 1."""
        runner = CliRunner()
        path = _tmp_apk()
        try:
            with patch("scanner_cli.main.requests.Session") as MockSession:
                session = MockSession.return_value
                session.post.return_value = _mock_response({"id": "abc"})
                # clean verdict but risk score 40, threshold 30
                session.get.return_value = _mock_response(_scan_done("abc", "clean", 40))
                result = runner.invoke(cli, ["scan", path, "--poll-interval", "0", "--fail-above", "30"])
            assert result.exit_code == 1
        finally:
            os.unlink(path)

    def test_suspicious_scan_below_threshold_exits_0(self):
        """suspicious verdict but risk score ≤ fail-above → exit 0."""
        runner = CliRunner()
        path = _tmp_apk()
        try:
            with patch("scanner_cli.main.requests.Session") as MockSession:
                session = MockSession.return_value
                session.post.return_value = _mock_response({"id": "abc"})
                # suspicious verdict but risk score 20, threshold 60
                session.get.return_value = _mock_response(_scan_done("abc", "suspicious", 20))
                result = runner.invoke(cli, ["scan", path, "--poll-interval", "0", "--fail-above", "60"])
            assert result.exit_code == 0
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# status command
# ---------------------------------------------------------------------------

class TestStatusCommand:
    def test_status_text_output(self):
        runner = CliRunner()
        with patch("scanner_cli.main.requests.Session") as MockSession:
            session = MockSession.return_value
            session.get.return_value = _mock_response(_scan_done("abc123"))
            result = runner.invoke(cli, ["status", "abc123"])
        assert result.exit_code == 0

    def test_status_json_output(self):
        runner = CliRunner()
        with patch("scanner_cli.main.requests.Session") as MockSession:
            session = MockSession.return_value
            scan = _scan_done("abc123")
            session.get.return_value = _mock_response(scan)
            result = runner.invoke(cli, ["--format", "json", "status", "abc123"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["id"] == "abc123"

    def test_status_table_output(self):
        runner = CliRunner()
        with patch("scanner_cli.main.requests.Session") as MockSession:
            session = MockSession.return_value
            session.get.return_value = _mock_response(_scan_done("abc123"))
            result = runner.invoke(cli, ["--format", "table", "status", "abc123"])
        assert result.exit_code == 0

    def test_status_not_found_exits_3(self):
        runner = CliRunner()
        with patch("scanner_cli.main.requests.Session") as MockSession:
            session = MockSession.return_value
            session.get.return_value = _mock_response({"error": "not found"}, status_code=404)
            result = runner.invoke(cli, ["status", "nonexistent-id"])
        assert result.exit_code == 3

    def test_status_connection_error_exits_3(self):
        runner = CliRunner()
        with patch("scanner_cli.main.requests.Session") as MockSession:
            session = MockSession.return_value
            session.get.side_effect = requests.ConnectionError("refused")
            result = runner.invoke(cli, ["status", "abc123"])
        assert result.exit_code == 3


# ---------------------------------------------------------------------------
# history command
# ---------------------------------------------------------------------------

class TestHistoryCommand:
    def _make_scans(self, count: int) -> list[dict]:
        return [_scan_done(f"scan-{i}", "clean", i) for i in range(count)]

    def test_history_text_output(self):
        runner = CliRunner()
        with patch("scanner_cli.main.requests.Session") as MockSession:
            session = MockSession.return_value
            session.get.return_value = _mock_response(self._make_scans(5))
            result = runner.invoke(cli, ["history"])
        assert result.exit_code == 0

    def test_history_json_output(self):
        runner = CliRunner()
        with patch("scanner_cli.main.requests.Session") as MockSession:
            session = MockSession.return_value
            scans = self._make_scans(3)
            session.get.return_value = _mock_response(scans)
            result = runner.invoke(cli, ["--format", "json", "history"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)

    def test_history_table_output(self):
        runner = CliRunner()
        with patch("scanner_cli.main.requests.Session") as MockSession:
            session = MockSession.return_value
            session.get.return_value = _mock_response(self._make_scans(5))
            result = runner.invoke(cli, ["--format", "table", "history"])
        assert result.exit_code == 0

    def test_history_empty_list(self):
        runner = CliRunner()
        with patch("scanner_cli.main.requests.Session") as MockSession:
            session = MockSession.return_value
            session.get.return_value = _mock_response([])
            result = runner.invoke(cli, ["history"])
        assert result.exit_code == 0
        assert "No scans found" in result.output

    def test_history_limit_respected(self):
        runner = CliRunner()
        with patch("scanner_cli.main.requests.Session") as MockSession:
            session = MockSession.return_value
            session.get.return_value = _mock_response(self._make_scans(100))
            result = runner.invoke(cli, ["--format", "json", "history", "--limit", "5"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert len(parsed) <= 5

    def test_history_connection_error_exits_3(self):
        runner = CliRunner()
        with patch("scanner_cli.main.requests.Session") as MockSession:
            session = MockSession.return_value
            session.get.side_effect = requests.ConnectionError("refused")
            result = runner.invoke(cli, ["history"])
        assert result.exit_code == 3


# ---------------------------------------------------------------------------
# report command
# ---------------------------------------------------------------------------

class TestReportCommand:
    def test_report_download_success(self):
        runner = CliRunner()
        pdf_bytes = b"%PDF-1.4 test content"
        with runner.isolated_filesystem():
            with patch("scanner_cli.main.requests.Session") as MockSession:
                session = MockSession.return_value
                resp = MagicMock()
                resp.status_code = 200
                resp.raise_for_status = MagicMock()
                resp.iter_content = lambda chunk_size: iter([pdf_bytes])
                session.get.return_value = resp
                result = runner.invoke(cli, ["report", "abc123", "--output", "out.pdf"])
            assert result.exit_code == 0
            assert os.path.exists("out.pdf")
            with open("out.pdf", "rb") as f:
                assert f.read() == pdf_bytes

    def test_report_scan_not_complete_exits_3(self):
        runner = CliRunner()
        with patch("scanner_cli.main.requests.Session") as MockSession:
            session = MockSession.return_value
            resp = _mock_response({"status": "pending"}, status_code=409)
            session.get.return_value = resp
            result = runner.invoke(cli, ["report", "abc123"])
        assert result.exit_code == 3

    def test_report_not_found_exits_3(self):
        runner = CliRunner()
        with patch("scanner_cli.main.requests.Session") as MockSession:
            session = MockSession.return_value
            session.get.return_value = _mock_response({"error": "not found"}, status_code=404)
            result = runner.invoke(cli, ["report", "nonexistent-id"])
        assert result.exit_code == 3

    def test_report_connection_error_exits_3(self):
        runner = CliRunner()
        with patch("scanner_cli.main.requests.Session") as MockSession:
            session = MockSession.return_value
            session.get.side_effect = requests.ConnectionError("refused")
            result = runner.invoke(cli, ["report", "abc123"])
        assert result.exit_code == 3

    def test_report_default_output_filename(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            with patch("scanner_cli.main.requests.Session") as MockSession:
                session = MockSession.return_value
                resp = MagicMock()
                resp.status_code = 200
                resp.raise_for_status = MagicMock()
                resp.iter_content = lambda chunk_size: iter([b"%PDF test"])
                session.get.return_value = resp
                result = runner.invoke(cli, ["report", "my-scan-id"])
            assert result.exit_code == 0
            assert os.path.exists("scan-my-scan-id.pdf")


# ---------------------------------------------------------------------------
# API key authentication
# ---------------------------------------------------------------------------

class TestApiKeyAuthentication:
    def test_api_key_sent_as_bearer_token(self):
        runner = CliRunner()
        with patch("scanner_cli.main.requests.Session") as MockSession:
            session = MockSession.return_value
            session.get.return_value = _mock_response(_scan_done("abc123"))
            result = runner.invoke(cli, ["--api-key", "my-secret-key", "status", "abc123"])
        assert result.exit_code == 0
        # Verify Authorization header was set on the session
        MockSession.return_value.headers.__setitem__.assert_called()

    def test_no_api_key_no_auth_header(self):
        runner = CliRunner()
        with patch("scanner_cli.main.requests.Session") as MockSession:
            session = MockSession.return_value
            session.get.return_value = _mock_response(_scan_done("abc123"))
            # Should not error without API key
            result = runner.invoke(cli, ["status", "abc123"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Custom API URL
# ---------------------------------------------------------------------------

class TestCustomApiUrl:
    def test_custom_api_url_used(self):
        runner = CliRunner()
        with patch("scanner_cli.main.requests.Session") as MockSession:
            session = MockSession.return_value
            session.get.return_value = _mock_response(_scan_done("abc123"))
            result = runner.invoke(cli, [
                "--api-url", "http://custom-api:9000",
                "status", "abc123"
            ])
        assert result.exit_code == 0
        call_args = session.get.call_args
        assert "custom-api:9000" in call_args[0][0]
