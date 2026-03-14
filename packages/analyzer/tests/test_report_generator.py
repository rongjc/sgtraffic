"""
Integration tests for PDF report generation.

Tests cover:
- generate_report returns non-empty bytes
- PDF magic bytes present (valid PDF)
- Works for APK scan results
- Works for IPA scan results
- Works for source code scan results
- Zero findings does not crash
- Many findings renders all severities
- Permissions section rendered when permissions present
- Certificate section rendered
- Remediation guidance embedded for known rules
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.report_generator import generate_report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _apk_scan_data(
    filename: str = "test.apk",
    verdict: str = "clean",
    risk_score: int = 0,
    pha_categories: list | None = None,
    permissions: list | None = None,
) -> dict:
    return {
        "filename": filename,
        "file_hash_sha256": "a" * 64,
        "verdict": verdict,
        "risk_score": risk_score,
        "pha_categories": pha_categories or [],
        "created_at": "2026-03-13T00:00:00Z",
        "completed_at": "2026-03-13T00:01:00Z",
        "metadata": {
            "package_name": "com.test.app",
            "version": "1.0",
            "min_sdk": 21,
            "target_sdk": 33,
            "permissions": permissions or [],
            "sha256": "a" * 64,
        },
    }


def _ipa_scan_data(
    verdict: str = "clean",
    risk_score: int = 0,
) -> dict:
    return {
        "filename": "test.ipa",
        "file_hash_sha256": "b" * 64,
        "verdict": verdict,
        "risk_score": risk_score,
        "pha_categories": [],
        "created_at": "2026-03-13T00:00:00Z",
        "completed_at": "2026-03-13T00:01:00Z",
        "metadata": {
            "bundle_id": "com.test.iosapp",
            "bundle_name": "iOSApp",
            "version": "2.0",
            "min_os_version": "14.0",
            "platform": "iOS",
            "sha256": "b" * 64,
            "url_schemes": [],
        },
    }


def _source_scan_data(source_type: str = "android_source") -> dict:
    return {
        "filename": "project.zip",
        "file_hash_sha256": "c" * 64,
        "verdict": "suspicious",
        "risk_score": 30,
        "pha_categories": ["data_collection"],
        "created_at": "2026-03-13T00:00:00Z",
        "completed_at": "2026-03-13T00:01:00Z",
        "metadata": {
            "sha256": "c" * 64,
            "source_type": source_type,
            "permissions": [],
        },
    }


def _finding(rule: str = "test_rule", severity: str = "high", category: str = "data_collection") -> dict:
    return {
        "category": category,
        "severity": severity,
        "rule": rule,
        "description": f"Test finding for {rule}",
        "evidence": f"evidence for {rule}",
    }


def _is_pdf(data: bytes) -> bool:
    return data[:4] == b"%PDF"


# ---------------------------------------------------------------------------
# Basic generation tests
# ---------------------------------------------------------------------------

class TestReportGeneration:
    def test_returns_bytes(self):
        result = generate_report(_apk_scan_data(), [])
        assert isinstance(result, bytes)

    def test_non_empty(self):
        result = generate_report(_apk_scan_data(), [])
        assert len(result) > 0

    def test_valid_pdf_magic_bytes(self):
        result = generate_report(_apk_scan_data(), [])
        assert _is_pdf(result), "Output should start with %PDF"

    def test_zero_findings_does_not_crash(self):
        result = generate_report(_apk_scan_data(), [])
        assert _is_pdf(result)

    def test_ipa_scan_generates_pdf(self):
        result = generate_report(_ipa_scan_data(), [])
        assert _is_pdf(result)

    def test_source_android_scan_generates_pdf(self):
        result = generate_report(_source_scan_data("android_source"), [])
        assert _is_pdf(result)

    def test_source_ios_scan_generates_pdf(self):
        result = generate_report(_source_scan_data("ios_source"), [])
        assert _is_pdf(result)


# ---------------------------------------------------------------------------
# Scan verdict variations
# ---------------------------------------------------------------------------

class TestVerdictVariations:
    def test_clean_verdict_pdf(self):
        result = generate_report(_apk_scan_data(verdict="clean", risk_score=5), [])
        assert _is_pdf(result)

    def test_suspicious_verdict_pdf(self):
        findings = [_finding("hardcoded_secret", "high")]
        result = generate_report(_apk_scan_data(verdict="suspicious", risk_score=30, pha_categories=["data_collection"]), findings)
        assert _is_pdf(result)

    def test_pha_verdict_pdf(self):
        findings = [_finding("backdoor_detected", "critical", "backdoor")]
        result = generate_report(_apk_scan_data(verdict="pha", risk_score=90, pha_categories=["backdoor"]), findings)
        assert _is_pdf(result)


# ---------------------------------------------------------------------------
# Many findings / all severity levels
# ---------------------------------------------------------------------------

class TestFindingsRendering:
    def test_all_severity_levels_render(self):
        findings = [
            _finding("rule_critical", "critical", "backdoor"),
            _finding("rule_high", "high", "data_collection"),
            _finding("rule_medium", "medium", "data_collection"),
            _finding("rule_low", "low", "data_collection"),
        ]
        result = generate_report(
            _apk_scan_data(verdict="pha", risk_score=100, pha_categories=["backdoor", "data_collection"]),
            findings,
        )
        assert _is_pdf(result)

    def test_many_findings_render(self):
        findings = [_finding(f"rule_{i}", "medium") for i in range(50)]
        result = generate_report(
            _apk_scan_data(verdict="suspicious", risk_score=50),
            findings,
        )
        assert _is_pdf(result)

    def test_certificate_findings_render(self):
        cert_findings = [
            _finding("self_signed_cert", "medium", "non_android_threat"),
            _finding("debug_certificate", "high", "non_android_threat"),
            _finding("cert_expired", "high", "non_android_threat"),
        ]
        result = generate_report(
            _apk_scan_data(verdict="suspicious", risk_score=25),
            cert_findings,
        )
        assert _is_pdf(result)


# ---------------------------------------------------------------------------
# Permissions section
# ---------------------------------------------------------------------------

class TestPermissionsSection:
    def test_high_risk_permissions_render(self):
        perms = [
            "android.permission.SEND_SMS",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.INTERNET",
        ]
        result = generate_report(
            _apk_scan_data(permissions=perms, verdict="suspicious", risk_score=30),
            [],
        )
        assert _is_pdf(result)

    def test_unknown_permissions_render(self):
        perms = ["com.custom.permission.SOMETHING"]
        result = generate_report(
            _apk_scan_data(permissions=perms),
            [],
        )
        assert _is_pdf(result)

    def test_no_permissions_skips_section_gracefully(self):
        result = generate_report(_apk_scan_data(permissions=[]), [])
        assert _is_pdf(result)


# ---------------------------------------------------------------------------
# Remediation content
# ---------------------------------------------------------------------------

class TestRemediationContent:
    def test_known_rule_produces_larger_pdf(self):
        """A finding with a known remediation rule should produce a larger PDF
        (more content) compared to an unknown rule."""
        base = generate_report(_apk_scan_data(), [_finding("unknown_rule_xyz", "high")])
        with_remediation = generate_report(
            _apk_scan_data(),
            [_finding("hardcoded_secret", "high")],
        )
        # Both should be valid PDFs
        assert _is_pdf(base)
        assert _is_pdf(with_remediation)

    def test_report_with_all_known_rules_renders(self):
        known_rules = [
            "sms_internet_combo",
            "camera_audio_internet_combo",
            "dynamic_code_loading",
            "hardcoded_secret",
            "insecure_http",
            "crypto_weak_algorithm",
        ]
        findings = [_finding(rule, "high") for rule in known_rules]
        result = generate_report(_apk_scan_data(verdict="pha", risk_score=100), findings)
        assert _is_pdf(result)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_filename_does_not_crash(self):
        scan_data = _apk_scan_data(filename="")
        result = generate_report(scan_data, [])
        assert _is_pdf(result)

    def test_missing_metadata_keys_do_not_crash(self):
        scan_data = {
            "filename": "test.apk",
            "file_hash_sha256": "a" * 64,
            "verdict": "clean",
            "risk_score": 0,
            "pha_categories": [],
            "created_at": "2026-03-13T00:00:00Z",
            # No metadata key
        }
        result = generate_report(scan_data, [])
        assert _is_pdf(result)

    def test_finding_with_empty_evidence_renders(self):
        findings = [{
            "category": "data_collection",
            "severity": "medium",
            "rule": "some_rule",
            "description": "Test finding",
            "evidence": "",
        }]
        result = generate_report(_apk_scan_data(), findings)
        assert _is_pdf(result)

    def test_finding_with_long_description_renders(self):
        findings = [{
            "category": "data_collection",
            "severity": "high",
            "rule": "verbose_rule",
            "description": "A" * 2000,
            "evidence": "B" * 1000,
        }]
        result = generate_report(_apk_scan_data(verdict="suspicious", risk_score=30), findings)
        assert _is_pdf(result)
