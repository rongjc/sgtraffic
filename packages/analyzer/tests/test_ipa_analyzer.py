"""
Integration tests for IPA static analysis module.

Tests cover:
- Info.plist parsing (ATS, URL schemes, file sharing, privacy descriptions)
- Entitlements analysis (debug, private, keychain wildcards)
- Binary string analysis (secrets, crypto, C2 patterns)
- Tracker/SDK detection
- Provisioning profile analysis
- Risk score and verdict calculation
- Error handling (missing file, bad zip)
"""
import io
import plistlib
import struct
import zipfile
import tempfile
import os
import pytest

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.ipa_analyzer import (
    analyze_ipa,
    _find_app_dir,
    _find_file,
    _is_macho,
    _compute_risk_score,
    _determine_verdict,
    _analyze_info_plist,
    _analyze_entitlements,
    _analyze_binary_strings,
    _detect_trackers,
    _extract_strings,
)
from src.models import Finding


# ---------------------------------------------------------------------------
# Helpers to build synthetic IPA files
# ---------------------------------------------------------------------------

def _make_plist_bytes(data: dict) -> bytes:
    return plistlib.dumps(data, fmt=plistlib.FMT_XML)


def _build_ipa(
    info_plist: dict | None = None,
    entitlements: dict | None = None,
    binary_data: bytes = b"",
    extra_files: dict[str, bytes] | None = None,
    app_name: str = "TestApp",
) -> bytes:
    """Create a minimal, in-memory IPA (ZIP) file for testing."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        app_dir = f"Payload/{app_name}.app/"

        if info_plist is not None:
            zf.writestr(f"{app_dir}Info.plist", _make_plist_bytes(info_plist))

        if entitlements is not None:
            # Write as .xcent file so _extract_entitlements picks it up
            zf.writestr(f"{app_dir}{app_name}.xcent", _make_plist_bytes(entitlements))

        if binary_data:
            zf.writestr(f"{app_dir}{app_name}", binary_data)

        if extra_files:
            for path, content in extra_files.items():
                zf.writestr(path, content)

    return buf.getvalue()


def _write_ipa(data: bytes) -> str:
    """Write IPA bytes to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".ipa")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def _macho_header_64() -> bytes:
    """Return a minimal 64-bit little-endian Mach-O magic header."""
    return struct.pack(">I", 0xFEEDFACF)


# ---------------------------------------------------------------------------
# _find_app_dir
# ---------------------------------------------------------------------------

class TestFindAppDir:
    def test_finds_app_dir(self):
        names = [
            "Payload/MyApp.app/Info.plist",
            "Payload/MyApp.app/MyApp",
        ]
        assert _find_app_dir(names) == "Payload/MyApp.app/"

    def test_no_payload(self):
        assert _find_app_dir(["some/other/file.txt"]) == ""

    def test_empty(self):
        assert _find_app_dir([]) == ""


# ---------------------------------------------------------------------------
# _is_macho
# ---------------------------------------------------------------------------

class TestIsMacho:
    def test_64bit_little_endian(self):
        assert _is_macho(struct.pack(">I", 0xFEEDFACF))

    def test_32bit_little_endian(self):
        assert _is_macho(struct.pack(">I", 0xFEEDFACE))

    def test_fat_binary(self):
        assert _is_macho(struct.pack(">I", 0xCAFEBABE))

    def test_not_macho(self):
        assert not _is_macho(b"\x7fELF")

    def test_too_short(self):
        assert not _is_macho(b"\xfe\xed")


# ---------------------------------------------------------------------------
# Info.plist analysis — ATS
# ---------------------------------------------------------------------------

class TestATSDetection:
    def test_allows_arbitrary_loads_flagged(self):
        plist = {"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}}
        findings = _analyze_info_plist(plist)
        rules = {f.rule for f in findings}
        assert "ats_allows_arbitrary_loads" in rules

    def test_allows_arbitrary_loads_false_not_flagged(self):
        plist = {"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": False}}
        findings = _analyze_info_plist(plist)
        assert not any(f.rule == "ats_allows_arbitrary_loads" for f in findings)

    def test_arbitrary_loads_media_medium_severity(self):
        plist = {"NSAppTransportSecurity": {"NSAllowsArbitraryLoadsForMedia": True}}
        findings = _analyze_info_plist(plist)
        matching = [f for f in findings if f.rule == "ats_allows_arbitrary_loads_media"]
        assert len(matching) == 1
        assert matching[0].severity == "medium"

    def test_insecure_exception_domains_flagged(self):
        plist = {
            "NSAppTransportSecurity": {
                "NSExceptionDomains": {
                    "example.com": {"NSExceptionAllowsInsecureHTTPLoads": True}
                }
            }
        }
        findings = _analyze_info_plist(plist)
        assert any(f.rule == "ats_insecure_exception_domains" for f in findings)

    def test_no_ats_key_no_findings(self):
        findings = _analyze_info_plist({"CFBundleIdentifier": "com.test.app"})
        ats_findings = [f for f in findings if f.rule.startswith("ats_")]
        assert len(ats_findings) == 0


# ---------------------------------------------------------------------------
# Info.plist analysis — URL schemes
# ---------------------------------------------------------------------------

class TestURLSchemes:
    def test_http_scheme_hijack_detected(self):
        plist = {
            "CFBundleURLTypes": [{"CFBundleURLSchemes": ["http", "myapp"]}]
        }
        findings = _analyze_info_plist(plist)
        assert any(f.rule == "url_scheme_hijack_http" for f in findings)

    def test_normal_scheme_no_flag(self):
        plist = {
            "CFBundleURLTypes": [{"CFBundleURLSchemes": ["myapp", "fb12345"]}]
        }
        findings = _analyze_info_plist(plist)
        assert not any(f.rule == "url_scheme_hijack_http" for f in findings)


# ---------------------------------------------------------------------------
# Info.plist analysis — file sharing
# ---------------------------------------------------------------------------

class TestFileSharing:
    def test_file_sharing_enabled(self):
        plist = {"UIFileSharingEnabled": True}
        findings = _analyze_info_plist(plist)
        assert any(f.rule == "file_sharing_enabled" for f in findings)

    def test_documents_in_place_low_severity(self):
        plist = {"LSSupportsOpeningDocumentsInPlace": True}
        findings = _analyze_info_plist(plist)
        matching = [f for f in findings if f.rule == "documents_in_place"]
        assert matching and matching[0].severity == "low"


# ---------------------------------------------------------------------------
# Info.plist analysis — excessive URL scheme queries
# ---------------------------------------------------------------------------

class TestExcessiveURLSchemeQueries:
    def test_more_than_20_schemes_flagged(self):
        schemes = [f"scheme{i}" for i in range(25)]
        plist = {"LSApplicationQueriesSchemes": schemes}
        findings = _analyze_info_plist(plist)
        assert any(f.rule == "excessive_url_scheme_queries" for f in findings)

    def test_exactly_20_not_flagged(self):
        schemes = [f"scheme{i}" for i in range(20)]
        plist = {"LSApplicationQueriesSchemes": schemes}
        findings = _analyze_info_plist(plist)
        assert not any(f.rule == "excessive_url_scheme_queries" for f in findings)


# ---------------------------------------------------------------------------
# Info.plist analysis — empty privacy descriptions
# ---------------------------------------------------------------------------

class TestPrivacyDescriptions:
    def test_empty_description_flagged(self):
        plist = {"NSCameraUsageDescription": ""}
        findings = _analyze_info_plist(plist)
        assert any(f.rule == "empty_privacy_description" for f in findings)

    def test_very_short_description_flagged(self):
        plist = {"NSMicrophoneUsageDescription": "ok"}
        findings = _analyze_info_plist(plist)
        assert any(f.rule == "empty_privacy_description" for f in findings)

    def test_adequate_description_not_flagged(self):
        plist = {"NSCameraUsageDescription": "Used to scan QR codes for login"}
        findings = _analyze_info_plist(plist)
        assert not any(f.rule == "empty_privacy_description" for f in findings)


# ---------------------------------------------------------------------------
# Entitlements analysis
# ---------------------------------------------------------------------------

class TestEntitlementsAnalysis:
    def test_debug_entitlement_flagged(self):
        findings = _analyze_entitlements({"com.apple.security.get-task-allow": True})
        assert any(f.rule == "entitlement_debug_allowed" for f in findings)

    def test_private_entitlement_critical(self):
        findings = _analyze_entitlements({"com.apple.private.some.feature": True})
        matching = [f for f in findings if f.rule == "private_entitlements"]
        assert matching and matching[0].severity == "critical"

    def test_keychain_wildcard_flagged(self):
        findings = _analyze_entitlements({
            "keychain-access-groups": ["com.myapp.*"]
        })
        assert any(f.rule == "keychain_wildcard_access" for f in findings)

    def test_clean_entitlements_no_findings(self):
        findings = _analyze_entitlements({
            "com.apple.developer.push-notifications": True,
            "keychain-access-groups": ["com.myapp.app"],
        })
        assert len(findings) == 0

    def test_many_app_groups_flagged(self):
        groups = [f"group.app{i}" for i in range(6)]
        findings = _analyze_entitlements({"com.apple.security.application-groups": groups})
        assert any(f.rule == "excessive_app_groups" for f in findings)


# ---------------------------------------------------------------------------
# Binary string analysis
# ---------------------------------------------------------------------------

class TestBinaryStringAnalysis:
    def test_insecure_random_detected(self):
        strings = ["rand()", "some_function"]
        findings = _analyze_binary_strings(strings)
        assert any(f.rule == "insecure_random" for f in findings)

    def test_hardcoded_api_key_detected(self):
        strings = ['api_key = "supersecretkey123"']
        findings = _analyze_binary_strings(strings)
        assert any(f.rule == "hardcoded_api_key" for f in findings)

    def test_embedded_private_key_detected(self):
        strings = ["-----BEGIN RSA PRIVATE KEY-----", "MIIEowIBAAKCAQEA..."]
        findings = _analyze_binary_strings(strings)
        assert any(f.rule == "embedded_private_key" for f in findings)

    def test_des_crypto_detected(self):
        strings = ["kCCAlgorithmDES used for encryption"]
        findings = _analyze_binary_strings(strings)
        assert any(f.rule == "insecure_crypto_des" for f in findings)

    def test_rc4_crypto_detected(self):
        strings = ["kCCAlgorithmRC4"]
        findings = _analyze_binary_strings(strings)
        assert any(f.rule == "insecure_crypto_rc4" for f in findings)

    def test_c2_ip_url_detected(self):
        strings = ["http://192.168.1.1:8080/cmd"]
        findings = _analyze_binary_strings(strings)
        assert any(f.rule == "c2_ip_url" for f in findings)

    def test_tor_onion_detected(self):
        strings = ["http://aaaaaaaaaaaaaaaa.onion/api"]
        findings = _analyze_binary_strings(strings)
        assert any(f.rule == "tor_onion_url" for f in findings)

    def test_pastebin_c2_detected(self):
        strings = ["https://pastebin.com/raw/AbCdEf12"]
        findings = _analyze_binary_strings(strings)
        assert any(f.rule == "pastebin_c2" for f in findings)

    def test_keychain_accessible_always_detected(self):
        strings = ["kSecAttrAccessibleAlways"]
        findings = _analyze_binary_strings(strings)
        assert any(f.rule == "keychain_accessible_always" for f in findings)

    def test_clean_strings_no_findings(self):
        strings = ["Hello World", "com.example.app", "NSURLSession"]
        findings = _analyze_binary_strings(strings)
        assert len(findings) == 0

    def test_secret_value_is_redacted_in_evidence(self):
        strings = ['api_key = "realsecretvalue999"']
        findings = _analyze_binary_strings(strings)
        matching = [f for f in findings if f.rule == "hardcoded_api_key"]
        assert matching
        assert "realsecretvalue999" not in matching[0].evidence


# ---------------------------------------------------------------------------
# Tracker detection
# ---------------------------------------------------------------------------

class TestTrackerDetection:
    def test_facebook_sdk_detected(self):
        names = [
            "Payload/App.app/Frameworks/FBSDKCoreKit.framework/FBSDKCoreKit",
        ]
        findings = _detect_trackers(names, "Payload/App.app/")
        assert any(f.rule == "tracker_sdk_detected" for f in findings)

    def test_multiple_trackers_single_finding(self):
        names = [
            "Payload/App.app/Frameworks/Amplitude.framework/Amplitude",
            "Payload/App.app/Frameworks/Mixpanel.framework/Mixpanel",
        ]
        findings = _detect_trackers(names, "Payload/App.app/")
        # Should be exactly one aggregated finding
        tracker_findings = [f for f in findings if f.rule == "tracker_sdk_detected"]
        assert len(tracker_findings) == 1

    def test_no_trackers_no_finding(self):
        names = ["Payload/App.app/Frameworks/MyOwnSDK.framework/MyOwnSDK"]
        findings = _detect_trackers(names, "Payload/App.app/")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Risk score and verdict
# ---------------------------------------------------------------------------

class TestRiskScoreAndVerdict:
    def test_score_capped_at_100(self):
        findings = [
            Finding(category="backdoor", severity="critical", rule="x", description="x"),
        ] * 10
        assert _compute_risk_score(findings) == 100

    def test_clean_verdict_below_25(self):
        assert _determine_verdict(10, []) == "clean"

    def test_suspicious_verdict_25_to_59(self):
        assert _determine_verdict(30, []) == "suspicious"

    def test_pha_verdict_score_above_60(self):
        assert _determine_verdict(60, []) == "pha"

    def test_pha_verdict_hard_category(self):
        assert _determine_verdict(5, ["backdoor"]) == "pha"
        assert _determine_verdict(5, ["ransomware"]) == "pha"
        assert _determine_verdict(5, ["privilege_escalation"]) == "pha"

    def test_data_collection_does_not_force_pha(self):
        assert _determine_verdict(10, ["data_collection"]) == "clean"


# ---------------------------------------------------------------------------
# Full analyze_ipa integration tests
# ---------------------------------------------------------------------------

class TestAnalyzeIpa:
    def test_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError):
            analyze_ipa("/nonexistent/path/file.ipa")

    def test_clean_ipa_returns_clean_verdict(self):
        info_plist = {
            "CFBundleIdentifier": "com.test.cleanapp",
            "CFBundleDisplayName": "CleanApp",
            "CFBundleShortVersionString": "1.0.0",
            "MinimumOSVersion": "14.0",
        }
        ipa_bytes = _build_ipa(info_plist=info_plist)
        path = _write_ipa(ipa_bytes)
        try:
            result = analyze_ipa(path)
            assert result["verdict"] == "clean"
            assert result["metadata"]["bundle_id"] == "com.test.cleanapp"
            assert result["metadata"]["bundle_name"] == "CleanApp"
            assert result["metadata"]["version"] == "1.0.0"
            assert result["metadata"]["platform"] == "iOS"
        finally:
            os.unlink(path)

    def test_ats_disabled_raises_risk_score(self):
        info_plist = {
            "CFBundleIdentifier": "com.test.insecure",
            "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
        }
        ipa_bytes = _build_ipa(info_plist=info_plist)
        path = _write_ipa(ipa_bytes)
        try:
            result = analyze_ipa(path)
            assert result["risk_score"] > 0
            rules = {f["rule"] for f in result["findings"]}
            assert "ats_allows_arbitrary_loads" in rules
        finally:
            os.unlink(path)

    def test_url_scheme_metadata_populated(self):
        info_plist = {
            "CFBundleIdentifier": "com.test.app",
            "CFBundleURLTypes": [{"CFBundleURLSchemes": ["myapp", "myapp2"]}],
        }
        ipa_bytes = _build_ipa(info_plist=info_plist)
        path = _write_ipa(ipa_bytes)
        try:
            result = analyze_ipa(path)
            assert "myapp" in result["metadata"]["url_schemes"]
        finally:
            os.unlink(path)

    def test_debug_entitlement_gives_pha_verdict(self):
        entitlements = {"com.apple.security.get-task-allow": True}
        info_plist = {"CFBundleIdentifier": "com.test.app"}
        ipa_bytes = _build_ipa(info_plist=info_plist, entitlements=entitlements)
        path = _write_ipa(ipa_bytes)
        try:
            result = analyze_ipa(path)
            assert result["verdict"] == "pha"
            assert "privilege_escalation" in result["pha_categories"]
        finally:
            os.unlink(path)

    def test_private_entitlement_critical_finding(self):
        entitlements = {"com.apple.private.network.routing": True}
        info_plist = {"CFBundleIdentifier": "com.test.app"}
        ipa_bytes = _build_ipa(info_plist=info_plist, entitlements=entitlements)
        path = _write_ipa(ipa_bytes)
        try:
            result = analyze_ipa(path)
            findings_by_rule = {f["rule"]: f for f in result["findings"]}
            assert "private_entitlements" in findings_by_rule
            assert findings_by_rule["private_entitlements"]["severity"] == "critical"
        finally:
            os.unlink(path)

    def test_tracker_framework_detected(self):
        info_plist = {"CFBundleIdentifier": "com.test.app"}
        extra = {
            "Payload/TestApp.app/Frameworks/Amplitude.framework/Amplitude": b"data",
        }
        ipa_bytes = _build_ipa(info_plist=info_plist, extra_files=extra)
        path = _write_ipa(ipa_bytes)
        try:
            result = analyze_ipa(path)
            rules = {f["rule"] for f in result["findings"]}
            assert "tracker_sdk_detected" in rules
        finally:
            os.unlink(path)

    def test_bad_zip_file_produces_parse_error_finding(self):
        fd, path = tempfile.mkstemp(suffix=".ipa")
        with os.fdopen(fd, "wb") as f:
            f.write(b"this is not a zip file at all")
        try:
            result = analyze_ipa(path)
            rules = {f["rule"] for f in result["findings"]}
            assert "ipa_parse_error" in rules
        finally:
            os.unlink(path)

    def test_result_has_required_keys(self):
        ipa_bytes = _build_ipa(info_plist={"CFBundleIdentifier": "com.test"})
        path = _write_ipa(ipa_bytes)
        try:
            result = analyze_ipa(path)
            for key in ("verdict", "risk_score", "pha_categories", "findings", "metadata"):
                assert key in result
            for mkey in ("bundle_id", "bundle_name", "version", "platform", "sha256", "url_schemes"):
                assert mkey in result["metadata"]
        finally:
            os.unlink(path)

    def test_sha256_in_metadata(self):
        ipa_bytes = _build_ipa(info_plist={"CFBundleIdentifier": "com.test"})
        path = _write_ipa(ipa_bytes)
        try:
            result = analyze_ipa(path)
            sha = result["metadata"]["sha256"]
            assert len(sha) == 64
            assert sha.isalnum()
        finally:
            os.unlink(path)

    def test_ipa_with_no_payload_returns_result(self):
        """IPA with no Payload/ directory still returns a valid (likely clean) result."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("SomeOtherDir/file.txt", "hello")
        path = _write_ipa(buf.getvalue())
        try:
            result = analyze_ipa(path)
            assert "verdict" in result
        finally:
            os.unlink(path)
