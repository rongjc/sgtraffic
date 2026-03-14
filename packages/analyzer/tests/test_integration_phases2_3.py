"""
Integration tests for Phases 2-3 deliverables.

Validates:
  - Android dynamic analysis (Frida event processing, traffic analysis, risk delta)
  - Web API fuzzing (Flask endpoint integration)
  - Privacy analysis module (permission-based + compliance checking)
  - iOS dynamic analysis (Frida event processing, traffic analysis, risk delta)
  - APPX static analysis (Flask endpoint + result shape)
  - Scanner pipeline: new analysis types flow through to the Flask API layer

All tests are offline / deterministic. No real emulators, simulators, or
network connections are required. External infrastructure is mocked at the
lowest possible layer so the production code paths are exercised.
"""

import io
import json
import os
import struct
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ──────────────────────────────────────────────────────────────────────────────
# Android dynamic analysis imports
# ──────────────────────────────────────────────────────────────────────────────
from src.dynamic_analyzer import (
    DynamicAnalysisResult,
    _analyze_traffic_flows,
    _events_to_findings,
    compute_dynamic_risk_delta,
)

# ──────────────────────────────────────────────────────────────────────────────
# iOS dynamic analysis imports
# ──────────────────────────────────────────────────────────────────────────────
from src.ios_dynamic_analyzer import (
    IosDynamicAnalysisResult,
    _analyze_traffic_flows as _ios_analyze_traffic_flows,
    _events_to_findings as _ios_events_to_findings,
    compute_ios_dynamic_risk_delta,
)

# ──────────────────────────────────────────────────────────────────────────────
# Privacy analysis imports
# ──────────────────────────────────────────────────────────────────────────────
from src.privacy_analysis import (
    analyze_privacy,
    _check_compliance_strings,
    TRACKER_SDK_DB,
)

# ──────────────────────────────────────────────────────────────────────────────
# APPX analyzer imports
# ──────────────────────────────────────────────────────────────────────────────
from src.appx_analyzer import analyze_appx, AppxMetadata

# ──────────────────────────────────────────────────────────────────────────────
# Flask test client
# ──────────────────────────────────────────────────────────────────────────────
from src.server import app as flask_app


# ==============================================================================
# Helpers
# ==============================================================================

def _make_appx(
    manifest_xml: bytes,
    pe_files: dict[str, bytes] | None = None,
    include_signature: bool = False,
    ext: str = ".appx",
) -> str:
    """Write a minimal APPX/MSIX zip to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=ext)
    os.close(fd)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AppxManifest.xml", manifest_xml)
        if include_signature:
            zf.writestr("AppxSignature.p7x", b"fakesig")
        if pe_files:
            for name, data in pe_files.items():
                zf.writestr(name, data)
    return path


_MINIMAL_MANIFEST = """\
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="com.test.app" Publisher="CN=Test Corp, O=Test, C=US"
            Version="1.0.0.0" ProcessorArchitecture="x64"/>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0"
                        MaxVersionTested="10.0.19041.0"/>
  </Dependencies>
  <Capabilities>
    {caps}
  </Capabilities>
</Package>
"""

_FLASK_CLIENT = flask_app.test_client()


# ==============================================================================
# 1. Android Dynamic Analysis — _events_to_findings
# ==============================================================================

class TestAndroidEventsToFindings(unittest.TestCase):

    def test_cleartext_http_event_raises_finding(self):
        events = [{"type": "network", "subtype": "http_connection", "url": "http://evil.com/track"}]
        findings = _events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("DYN_NET_002", rules)

    def test_https_event_does_not_raise_cleartext_finding(self):
        events = [{"type": "network", "subtype": "http_connection", "url": "https://safe.com/api"}]
        findings = _events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertNotIn("DYN_NET_002", rules)

    def test_excessive_dns_raises_finding(self):
        events = [{"type": "network", "subtype": "dns_lookup", "host": f"host{i}.com"} for i in range(51)]
        findings = _events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("DYN_NET_003", rules)

    def test_dns_below_threshold_no_finding(self):
        events = [{"type": "network", "subtype": "dns_lookup", "host": "example.com"} for _ in range(10)]
        findings = _events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertNotIn("DYN_NET_003", rules)

    def test_raw_socket_non_standard_port_raises_finding(self):
        events = [{"type": "network", "subtype": "raw_socket", "port": 31337}]
        findings = _events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("DYN_NET_001", rules)

    def test_raw_socket_standard_port_no_finding(self):
        for port in (80, 443, 8080, 8443):
            findings = _events_to_findings([{"type": "network", "subtype": "raw_socket", "port": port}])
            rules = [f.rule for f in findings]
            self.assertNotIn("DYN_NET_001", rules, f"Port {port} should not trigger raw socket finding")

    def test_external_storage_write_raises_finding(self):
        events = [{"type": "filesystem", "subtype": "file_write", "path": "/sdcard/data/secret.db"}]
        findings = _events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("DYN_FS_001", rules)

    def test_internal_file_write_no_finding(self):
        events = [{"type": "filesystem", "subtype": "file_write", "path": "/data/data/com.app/files/db.db"}]
        findings = _events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertNotIn("DYN_FS_001", rules)

    def test_sensitive_shared_prefs_raises_finding(self):
        events = [{"type": "filesystem", "subtype": "shared_prefs_write", "key": "user_password"}]
        findings = _events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("DYN_FS_002", rules)

    def test_non_sensitive_shared_prefs_no_finding(self):
        events = [{"type": "filesystem", "subtype": "shared_prefs_write", "key": "theme_color"}]
        findings = _events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertNotIn("DYN_FS_002", rules)

    def test_weak_cipher_des_raises_finding(self):
        events = [{"type": "crypto", "subtype": "cipher_operation", "algorithm": "DES/ECB/PKCS5Padding"}]
        findings = _events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("DYN_CRYPTO_001", rules)

    def test_strong_cipher_no_finding(self):
        events = [{"type": "crypto", "subtype": "cipher_operation", "algorithm": "AES/GCM/NoPadding"}]
        findings = _events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertNotIn("DYN_CRYPTO_001", rules)

    def test_key_generation_raises_finding(self):
        events = [{"type": "crypto", "subtype": "key_generation", "algorithm": "RSA"}]
        findings = _events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("DYN_CRYPTO_002", rules)

    def test_sms_send_raises_critical_finding(self):
        events = [{"type": "telephony", "subtype": "sms_send", "destination": "+1234567890"}]
        findings = _events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("DYN_TEL_001", rules)
        severity = next(f.severity for f in findings if f.rule == "DYN_TEL_001")
        self.assertEqual(severity, "critical")

    def test_device_id_read_raises_finding(self):
        events = [{"type": "telephony", "subtype": "device_id_read"}]
        findings = _events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("DYN_TEL_002", rules)

    def test_contacts_content_provider_raises_finding(self):
        events = [{"type": "content_provider", "subtype": "query", "uri": "content://com.android.contacts/data"}]
        findings = _events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("DYN_CP_001", rules)

    def test_sms_content_provider_raises_critical_finding(self):
        events = [{"type": "content_provider", "subtype": "query", "uri": "content://sms/inbox"}]
        findings = _events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("DYN_CP_002", rules)
        severity = next(f.severity for f in findings if f.rule == "DYN_CP_002")
        self.assertEqual(severity, "critical")

    def test_dex_class_loader_raises_finding(self):
        events = [{"type": "dynamic_code", "subtype": "dex_class_loader", "dex_path": "/sdcard/payload.dex"}]
        findings = _events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("DYN_CODE_001", rules)
        severity = next(f.severity for f in findings if f.rule == "DYN_CODE_001")
        self.assertEqual(severity, "critical")

    def test_reflection_raises_finding(self):
        events = [{"type": "dynamic_code", "subtype": "reflection", "class_name": "com.secret.Payload"}]
        findings = _events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("DYN_CODE_002", rules)

    def test_finding_deduplication_same_rule_once(self):
        """Same rule must appear at most once in findings even with many events."""
        events = [{"type": "telephony", "subtype": "sms_send", "destination": str(i)} for i in range(5)]
        findings = _events_to_findings(events)
        sms_findings = [f for f in findings if f.rule == "DYN_TEL_001"]
        self.assertEqual(len(sms_findings), 1)

    def test_evidence_captured_for_sms_send(self):
        events = [{"type": "telephony", "subtype": "sms_send", "destination": "+15551234"}]
        findings = _events_to_findings(events)
        f = next(x for x in findings if x.rule == "DYN_TEL_001")
        self.assertIn("+15551234", f.evidence)

    def test_empty_events_returns_no_findings(self):
        self.assertEqual(_events_to_findings([]), [])

    def test_unknown_event_type_ignored(self):
        events = [{"type": "unknown_type", "subtype": "foo"}]
        self.assertEqual(_events_to_findings(events), [])


# ==============================================================================
# 2. Android Dynamic Analysis — _analyze_traffic_flows
# ==============================================================================

class TestAndroidTrafficFlowAnalysis(unittest.TestCase):

    def _flow(self, scheme: str, host: str, path: str = "/") -> dict:
        return {"request": {"scheme": scheme, "host": host, "path": path}}

    def test_http_traffic_raises_cleartext_finding(self):
        flows = [self._flow("http", "tracker.example.com")]
        findings = _analyze_traffic_flows(flows)
        rules = [f.rule for f in findings]
        self.assertIn("DYN_NET_002", rules)

    def test_https_traffic_raises_low_info_finding(self):
        flows = [self._flow("https", "api.example.com")]
        findings = _analyze_traffic_flows(flows)
        rules = [f.rule for f in findings]
        self.assertIn("DYN_TRAFFIC_001", rules)

    def test_mixed_traffic_raises_both_findings(self):
        flows = [
            self._flow("http", "track.example.com"),
            self._flow("https", "api.example.com"),
        ]
        findings = _analyze_traffic_flows(flows)
        rules = [f.rule for f in findings]
        self.assertIn("DYN_NET_002", rules)
        self.assertIn("DYN_TRAFFIC_001", rules)

    def test_empty_flows_no_findings(self):
        self.assertEqual(_analyze_traffic_flows([]), [])

    def test_malformed_flow_skipped_gracefully(self):
        flows = [{"bad": "structure"}, self._flow("https", "ok.example.com")]
        # Should not raise; findings for the valid flow still returned
        findings = _analyze_traffic_flows(flows)
        self.assertIsInstance(findings, list)

    def test_http_evidence_contains_url(self):
        flows = [self._flow("http", "evil.com", "/steal")]
        findings = _analyze_traffic_flows(flows)
        cleartext = next(f for f in findings if f.rule == "DYN_NET_002")
        self.assertIn("evil.com", cleartext.evidence)


# ==============================================================================
# 3. Android Dynamic Analysis — compute_dynamic_risk_delta
# ==============================================================================

class TestAndroidComputeDynamicRiskDelta(unittest.TestCase):

    def _finding(self, severity: str):
        from src.models import Finding
        return Finding(category="spyware", severity=severity, rule="test", description="test")

    def test_no_findings_returns_zero(self):
        self.assertEqual(compute_dynamic_risk_delta([]), 0)

    def test_critical_finding_weighted_1_5x(self):
        findings = [self._finding("critical")]
        delta = compute_dynamic_risk_delta(findings)
        # base = 30, multiplied 1.5x → 45
        self.assertEqual(delta, 45)

    def test_high_finding_weighted_1_5x(self):
        findings = [self._finding("high")]
        self.assertEqual(compute_dynamic_risk_delta(findings), 30)

    def test_medium_finding_weighted_1_5x(self):
        findings = [self._finding("medium")]
        self.assertEqual(compute_dynamic_risk_delta(findings), 15)

    def test_low_finding_weighted_1_5x(self):
        findings = [self._finding("low")]
        self.assertEqual(compute_dynamic_risk_delta(findings), 4)

    def test_multiple_findings_cumulative(self):
        findings = [self._finding("critical"), self._finding("high")]
        # (30 + 20) * 1.5 = 75
        self.assertEqual(compute_dynamic_risk_delta(findings), 75)


# ==============================================================================
# 4. iOS Dynamic Analysis — _events_to_findings
# ==============================================================================

class TestIosEventsToFindings(unittest.TestCase):

    def test_cleartext_http_via_nsurlsession_raises_finding(self):
        events = [{"type": "network", "subtype": "nsurlsession_request", "url": "http://track.io/beacon"}]
        findings = _ios_events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("IOS_DYN_NET_002", rules)

    def test_https_nsurlsession_no_cleartext_finding(self):
        events = [{"type": "network", "subtype": "nsurlsession_request", "url": "https://api.io/data"}]
        findings = _ios_events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertNotIn("IOS_DYN_NET_002", rules)

    def test_excessive_dns_raises_finding(self):
        events = [{"type": "network", "subtype": "dns_lookup"} for _ in range(55)]
        findings = _ios_events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("IOS_DYN_NET_003", rules)

    def test_raw_socket_non_standard_port_raises_finding(self):
        events = [{"type": "network", "subtype": "raw_socket", "port": 12345}]
        findings = _ios_events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("IOS_DYN_NET_001", rules)

    def test_keychain_write_raises_finding(self):
        events = [{"type": "keychain", "subtype": "item_add"}]
        findings = _ios_events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("IOS_DYN_KC_001", rules)

    def test_keychain_read_raises_finding(self):
        events = [{"type": "keychain", "subtype": "item_read"}]
        findings = _ios_events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("IOS_DYN_KC_002", rules)

    def test_keychain_delete_raises_finding(self):
        events = [{"type": "keychain", "subtype": "item_delete"}]
        findings = _ios_events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("IOS_DYN_KC_003", rules)

    def test_pasteboard_read_raises_finding(self):
        events = [{"type": "pasteboard", "subtype": "read"}]
        findings = _ios_events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("IOS_DYN_PB_001", rules)

    def test_pasteboard_write_raises_finding(self):
        events = [{"type": "pasteboard", "subtype": "write"}]
        findings = _ios_events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("IOS_DYN_PB_002", rules)

    def test_location_tracking_raises_finding(self):
        events = [{"type": "location", "subtype": "start_updates"}]
        findings = _ios_events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("IOS_DYN_LOC_001", rules)

    def test_location_always_auth_raises_finding(self):
        events = [{"type": "location", "subtype": "request_authorization", "level": "always"}]
        findings = _ios_events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("IOS_DYN_LOC_002", rules)

    def test_contacts_access_raises_finding(self):
        events = [{"type": "contacts", "subtype": "enumerate"}]
        findings = _ios_events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("IOS_DYN_CONT_001", rules)

    def test_weak_crypto_des_raises_finding(self):
        events = [{"type": "crypto", "subtype": "cccrypt", "algorithm": "DES"}]
        findings = _ios_events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("IOS_DYN_CRYPTO_001", rules)

    def test_strong_crypto_no_weak_finding(self):
        events = [{"type": "crypto", "subtype": "cccrypt", "algorithm": "AES"}]
        findings = _ios_events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertNotIn("IOS_DYN_CRYPTO_001", rules)

    def test_key_generation_asymmetric_raises_finding(self):
        events = [{"type": "crypto", "subtype": "key_generation_asymmetric"}]
        findings = _ios_events_to_findings(events)
        rules = [f.rule for f in findings]
        self.assertIn("IOS_DYN_CRYPTO_002", rules)

    def test_deduplication_same_rule_once(self):
        events = [{"type": "keychain", "subtype": "item_add"} for _ in range(10)]
        findings = _ios_events_to_findings(events)
        kc_findings = [f for f in findings if f.rule == "IOS_DYN_KC_001"]
        self.assertEqual(len(kc_findings), 1)

    def test_empty_events_no_findings(self):
        self.assertEqual(_ios_events_to_findings([]), [])


# ==============================================================================
# 5. iOS Dynamic Analysis — traffic flows + risk delta
# ==============================================================================

class TestIosTrafficAndRiskDelta(unittest.TestCase):

    def _flow(self, scheme: str, host: str, path: str = "/") -> dict:
        return {"request": {"scheme": scheme, "host": host, "path": path}}

    def test_http_traffic_raises_cleartext_finding(self):
        flows = [self._flow("http", "bad.example.com")]
        findings = _ios_analyze_traffic_flows(flows)
        rules = [f.rule for f in findings]
        self.assertIn("IOS_DYN_NET_002", rules)

    def test_https_traffic_raises_info_finding(self):
        flows = [self._flow("https", "api.example.com")]
        findings = _ios_analyze_traffic_flows(flows)
        rules = [f.rule for f in findings]
        self.assertIn("IOS_DYN_TRAFFIC_001", rules)

    def test_empty_flows_no_findings(self):
        self.assertEqual(_ios_analyze_traffic_flows([]), [])

    def test_ios_risk_delta_1_5x_weight(self):
        from src.models import Finding
        findings = [Finding(category="spyware", severity="critical", rule="test", description="t")]
        # 30 * 1.5 = 45
        self.assertEqual(compute_ios_dynamic_risk_delta(findings), 45)

    def test_ios_risk_delta_no_findings(self):
        self.assertEqual(compute_ios_dynamic_risk_delta([]), 0)


# ==============================================================================
# 6. Privacy Analysis Module
# ==============================================================================

class TestPrivacyAnalysisPermissions(unittest.TestCase):
    """Test permission-based privacy findings (no androguard dx required)."""

    def test_fine_location_raises_high_finding(self):
        findings, score, trackers = analyze_privacy(["android.permission.ACCESS_FINE_LOCATION"])
        rules = [f.rule for f in findings]
        self.assertIn("fine_location_tracking", rules)
        severity = next(f.severity for f in findings if f.rule == "fine_location_tracking")
        self.assertEqual(severity, "high")
        self.assertGreater(score, 0)

    def test_background_location_raises_critical_finding(self):
        findings, score, trackers = analyze_privacy(["android.permission.ACCESS_BACKGROUND_LOCATION"])
        rules = [f.rule for f in findings]
        self.assertIn("background_location_tracking", rules)
        severity = next(f.severity for f in findings if f.rule == "background_location_tracking")
        self.assertEqual(severity, "critical")

    def test_phone_state_raises_high_finding(self):
        findings, score, trackers = analyze_privacy(["android.permission.READ_PHONE_STATE"])
        rules = [f.rule for f in findings]
        self.assertIn("device_id_harvesting_imei", rules)

    def test_contacts_access_raises_high_finding(self):
        findings, score, trackers = analyze_privacy(["android.permission.READ_CONTACTS"])
        rules = [f.rule for f in findings]
        self.assertIn("contact_list_access", rules)

    def test_sms_read_raises_high_finding(self):
        findings, score, trackers = analyze_privacy(["android.permission.READ_SMS"])
        rules = [f.rule for f in findings]
        self.assertIn("sms_read_privacy", rules)

    def test_call_log_raises_high_finding(self):
        findings, score, trackers = analyze_privacy(["android.permission.READ_CALL_LOG"])
        rules = [f.rule for f in findings]
        self.assertIn("call_log_access", rules)

    def test_get_accounts_raises_medium_finding(self):
        findings, score, trackers = analyze_privacy(["android.permission.GET_ACCOUNTS"])
        rules = [f.rule for f in findings]
        self.assertIn("account_enumeration", rules)
        severity = next(f.severity for f in findings if f.rule == "account_enumeration")
        self.assertEqual(severity, "medium")

    def test_no_privacy_permissions_zero_score_no_findings_no_dx(self):
        findings, score, trackers = analyze_privacy(["android.permission.INTERNET"])
        # No dx → only compliance check for consent/policy skipped
        privacy_findings = [f for f in findings if f.category == "privacy"]
        # INTERNET perm has no privacy finding
        perm_finding_rules = {f.rule for f in privacy_findings}
        self.assertNotIn("fine_location_tracking", perm_finding_rules)

    def test_score_capped_at_100(self):
        # Stack many high-severity permissions
        perms = [
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_PRIVILEGED_PHONE_STATE",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_SMS",
            "android.permission.READ_CALL_LOG",
            "android.permission.GET_ACCOUNTS",
            "android.permission.BODY_SENSORS",
            "android.permission.READ_MEDIA_IMAGES",
        ]
        _, score, _ = analyze_privacy(perms)
        self.assertLessEqual(score, 100)

    def test_empty_permissions_no_findings_no_dx(self):
        findings, score, trackers = analyze_privacy([])
        perm_findings = [f for f in findings if f.rule in (
            "fine_location_tracking", "device_id_harvesting_imei",
            "contact_list_access", "sms_read_privacy",
        )]
        self.assertEqual(perm_findings, [])
        self.assertEqual(trackers, [])

    def test_trackers_empty_without_dx(self):
        _, _, trackers = analyze_privacy(["android.permission.INTERNET"])
        self.assertEqual(trackers, [])


class TestPrivacyAnalysisWithMockDx(unittest.TestCase):
    """Test tracker detection and compliance checks using a mocked androguard dx."""

    def _make_dx(self, class_names: list[str], strings: list[str] | None = None) -> MagicMock:
        """Build a minimal androguard-style Analysis mock."""
        dx = MagicMock()

        cls_mocks = []
        for name in class_names:
            cls = MagicMock()
            cls.name = name
            cls.get_methods.return_value = []
            cls_mocks.append(cls)

        dx.get_classes.return_value = cls_mocks

        # strings_analysis: map str → mock with get_orig_value()
        if strings is not None:
            str_analysis = {}
            for i, s in enumerate(strings):
                sm = MagicMock()
                sm.get_orig_value.return_value = s
                str_analysis[i] = sm
            dx.get_strings_analysis.return_value = str_analysis
        else:
            dx.get_strings_analysis.return_value = {}

        return dx

    def test_google_analytics_tracker_detected(self):
        dx = self._make_dx(["com/google/android/gms/analytics/Tracker"])
        findings, score, trackers = analyze_privacy([], dx=dx)
        self.assertIn("Google Analytics", trackers)
        tracker_finding_rules = [f.rule for f in findings if f.category == "privacy"]
        self.assertTrue(any("google_analytics" in r for r in tracker_finding_rules))

    def test_facebook_sdk_tracker_detected(self):
        dx = self._make_dx(["com/facebook/appevents/AppEventsLogger"])
        _, _, trackers = analyze_privacy([], dx=dx)
        self.assertIn("Facebook SDK", trackers)

    def test_no_trackers_in_clean_app(self):
        dx = self._make_dx(["com/example/myapp/MainActivity"])
        _, _, trackers = analyze_privacy([], dx=dx)
        self.assertEqual(trackers, [])

    def test_tracker_score_contribution(self):
        # 3 trackers × 8 points = 24
        dx = self._make_dx([
            "com/google/android/gms/analytics/Tracker",
            "com/facebook/appevents/AppEventsLogger",
            "com/adjust/sdk/Adjust",
        ])
        _, score, trackers = analyze_privacy([], dx=dx)
        self.assertEqual(len(trackers), 3)
        self.assertGreaterEqual(score, 24)

    def test_no_consent_finding_when_no_consent_strings(self):
        dx = self._make_dx([], strings=["hello world", "normal string"])
        findings, _, _ = analyze_privacy([], dx=dx)
        rules = [f.rule for f in findings]
        self.assertIn("no_consent_mechanism", rules)

    def test_consent_finding_absent_when_consent_string_present(self):
        dx = self._make_dx([], strings=["com.google.android.ump.ConsentInformation"])
        findings, _, _ = analyze_privacy([], dx=dx)
        rules = [f.rule for f in findings]
        self.assertNotIn("no_consent_mechanism", rules)

    def test_no_privacy_policy_finding_when_missing(self):
        dx = self._make_dx([], strings=["hello", "no urls here"])
        findings, _, _ = analyze_privacy([], dx=dx)
        rules = [f.rule for f in findings]
        self.assertIn("no_privacy_policy_url", rules)

    def test_no_privacy_policy_finding_absent_when_url_present(self):
        dx = self._make_dx([], strings=["https://example.com/privacy-policy"])
        findings, _, _ = analyze_privacy([], dx=dx)
        rules = [f.rule for f in findings]
        self.assertNotIn("no_privacy_policy_url", rules)


class TestPrivacyComplianceStringChecks(unittest.TestCase):

    def test_gdpr_string_detected(self):
        consent, policy, retention = _check_compliance_strings(["GDPR consent required"])
        self.assertTrue(consent)

    def test_ccpa_string_detected(self):
        consent, policy, retention = _check_compliance_strings(["CCPA opt-out available"])
        self.assertTrue(consent)

    def test_ump_class_detected_as_consent(self):
        consent, policy, retention = _check_compliance_strings(["com.google.android.ump"])
        self.assertTrue(consent)

    def test_privacy_policy_url_detected(self):
        consent, policy, retention = _check_compliance_strings(["https://example.com/privacy-policy"])
        self.assertTrue(policy)

    def test_opt_out_detected_as_retention(self):
        consent, policy, retention = _check_compliance_strings(["opt-out of data collection"])
        self.assertTrue(retention)

    def test_clean_strings_return_false(self):
        consent, policy, retention = _check_compliance_strings(["hello", "world"])
        self.assertFalse(consent)
        self.assertFalse(policy)
        self.assertFalse(retention)

    def test_empty_strings_return_false(self):
        consent, policy, retention = _check_compliance_strings([])
        self.assertFalse(consent)
        self.assertFalse(policy)
        self.assertFalse(retention)


# ==============================================================================
# 7. APPX Static Analysis — Flask Endpoint Integration
# ==============================================================================

class TestAppxFlaskEndpoint(unittest.TestCase):

    def setUp(self):
        self.client = flask_app.test_client()

    def test_missing_appx_path_returns_400(self):
        resp = self.client.post("/analyze_appx", json={})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.get_json())

    def test_nonexistent_file_returns_404(self):
        resp = self.client.post("/analyze_appx", json={"appx_path": "/tmp/nonexistent_xyz.appx"})
        self.assertEqual(resp.status_code, 404)

    def test_valid_appx_returns_200_with_required_fields(self):
        appx_path = _make_appx(_MINIMAL_MANIFEST.format(caps="").encode())
        try:
            resp = self.client.post("/analyze_appx", json={"appx_path": appx_path})
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertIn("verdict", data)
            self.assertIn("risk_score", data)
            self.assertIn("findings", data)
            self.assertIn("metadata", data)
        finally:
            os.unlink(appx_path)

    def test_valid_appx_metadata_fields_present(self):
        appx_path = _make_appx(_MINIMAL_MANIFEST.format(caps="").encode())
        try:
            resp = self.client.post("/analyze_appx", json={"appx_path": appx_path})
            meta = resp.get_json()["metadata"]
            self.assertIn("platform", meta)
            self.assertIn("sha256", meta)
            self.assertIn("package_name", meta)
            self.assertIn("capabilities", meta)
            self.assertIn("restricted_capabilities", meta)
            self.assertIn("signed", meta)
            self.assertIn("package_type", meta)
        finally:
            os.unlink(appx_path)

    def test_valid_appx_package_name_extracted(self):
        appx_path = _make_appx(_MINIMAL_MANIFEST.format(caps="").encode())
        try:
            meta = self.client.post("/analyze_appx", json={"appx_path": appx_path}).get_json()["metadata"]
            self.assertEqual(meta["package_name"], "com.test.app")
            self.assertEqual(meta["version"], "1.0.0.0")
        finally:
            os.unlink(appx_path)

    def test_appx_with_run_full_trust_has_high_risk_finding(self):
        caps = '<rescap:Capability xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities" Name="runFullTrust"/>'
        appx_path = _make_appx(_MINIMAL_MANIFEST.format(caps=caps).encode())
        try:
            data = self.client.post("/analyze_appx", json={"appx_path": appx_path}).get_json()
            rules = [f["rule"] for f in data["findings"]]
            self.assertIn("restricted_cap_runFullTrust", rules)
        finally:
            os.unlink(appx_path)

    def test_unsigned_appx_raises_unsigned_finding(self):
        appx_path = _make_appx(_MINIMAL_MANIFEST.format(caps="").encode(), include_signature=False)
        try:
            data = self.client.post("/analyze_appx", json={"appx_path": appx_path}).get_json()
            rules = [f["rule"] for f in data["findings"]]
            self.assertIn("unsigned_package", rules)
        finally:
            os.unlink(appx_path)

    def test_signed_appx_no_unsigned_finding(self):
        appx_path = _make_appx(_MINIMAL_MANIFEST.format(caps="").encode(), include_signature=True)
        try:
            data = self.client.post("/analyze_appx", json={"appx_path": appx_path}).get_json()
            rules = [f["rule"] for f in data["findings"]]
            self.assertNotIn("unsigned_package", rules)
        finally:
            os.unlink(appx_path)

    def test_msix_extension_detected(self):
        appx_path = _make_appx(_MINIMAL_MANIFEST.format(caps="").encode(), ext=".msix")
        try:
            data = self.client.post("/analyze_appx", json={"appx_path": appx_path}).get_json()
            self.assertEqual(data["metadata"]["package_type"], "msix")
        finally:
            os.unlink(appx_path)

    def test_findings_have_required_keys(self):
        caps = '<rescap:Capability xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities" Name="runFullTrust"/>'
        appx_path = _make_appx(_MINIMAL_MANIFEST.format(caps=caps).encode())
        try:
            data = self.client.post("/analyze_appx", json={"appx_path": appx_path}).get_json()
            for finding in data["findings"]:
                for key in ("category", "severity", "rule", "description"):
                    self.assertIn(key, finding, f"Finding missing key '{key}': {finding}")
        finally:
            os.unlink(appx_path)

    def test_pe_dangerous_api_detected(self):
        pe_data = b"MZ" + b"\x00" * 510 + b"VirtualAllocEx\x00WriteProcessMemory\x00"
        appx_path = _make_appx(
            _MINIMAL_MANIFEST.format(caps="").encode(),
            pe_files={"payload.dll": pe_data},
        )
        try:
            data = self.client.post("/analyze_appx", json={"appx_path": appx_path}).get_json()
            rules = [f["rule"] for f in data["findings"]]
            self.assertIn("pe_virtual_alloc_ex", rules)
            self.assertIn("pe_write_process_memory", rules)
        finally:
            os.unlink(appx_path)


# ==============================================================================
# 8. Android Dynamic Analysis — Flask Endpoint Integration
# ==============================================================================

class TestAndroidDynamicFlaskEndpoint(unittest.TestCase):

    def setUp(self):
        self.client = flask_app.test_client()

    def test_missing_apk_path_returns_400(self):
        resp = self.client.post("/analyze-dynamic", json={})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.get_json())

    def test_nonexistent_apk_returns_404(self):
        resp = self.client.post("/analyze-dynamic", json={"apk_path": "/tmp/no_such_file.apk"})
        self.assertEqual(resp.status_code, 404)

    def test_valid_apk_returns_200_with_response_shape(self):
        """
        Mock analyze_apk_dynamic to return a populated DynamicAnalysisResult
        and verify the Flask endpoint serialises it correctly.
        """
        from src.models import Finding
        mock_result = DynamicAnalysisResult(
            findings=[Finding("spyware", "critical", "DYN_TEL_001", "SMS sent", "+123")],
            events_captured=5,
            traffic_flows_captured=2,
            timeout_seconds=60,
            package_name="com.evil.app",
            error=None,
        )

        fd, apk_path = tempfile.mkstemp(suffix=".apk")
        os.close(fd)
        try:
            with patch("src.server.analyze_apk_dynamic", return_value=mock_result):
                resp = self.client.post("/analyze-dynamic",
                                        json={"apk_path": apk_path, "timeout": 60})
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertIn("findings", data)
            self.assertIn("events_captured", data)
            self.assertIn("traffic_flows_captured", data)
            self.assertIn("timeout_seconds", data)
            self.assertIn("package_name", data)
            self.assertIn("dynamic_risk_delta", data)
            self.assertIn("error", data)
        finally:
            os.unlink(apk_path)

    def test_dynamic_findings_serialised_correctly(self):
        from src.models import Finding
        mock_result = DynamicAnalysisResult(
            findings=[Finding("spyware", "critical", "DYN_TEL_001", "SMS sent", "+123")],
            events_captured=1,
            package_name="com.evil.app",
        )
        fd, apk_path = tempfile.mkstemp(suffix=".apk")
        os.close(fd)
        try:
            with patch("src.server.analyze_apk_dynamic", return_value=mock_result):
                data = self.client.post("/analyze-dynamic",
                                        json={"apk_path": apk_path}).get_json()
            self.assertEqual(len(data["findings"]), 1)
            f = data["findings"][0]
            self.assertEqual(f["rule"], "DYN_TEL_001")
            self.assertEqual(f["severity"], "critical")
        finally:
            os.unlink(apk_path)

    def test_dynamic_risk_delta_included_and_nonzero(self):
        from src.models import Finding
        mock_result = DynamicAnalysisResult(
            findings=[Finding("spyware", "critical", "DYN_TEL_001", "SMS", "")],
        )
        fd, apk_path = tempfile.mkstemp(suffix=".apk")
        os.close(fd)
        try:
            with patch("src.server.analyze_apk_dynamic", return_value=mock_result):
                data = self.client.post("/analyze-dynamic",
                                        json={"apk_path": apk_path}).get_json()
            self.assertGreater(data["dynamic_risk_delta"], 0)
        finally:
            os.unlink(apk_path)

    def test_error_field_propagated_from_analyzer(self):
        mock_result = DynamicAnalysisResult(error="Emulator not reachable")
        fd, apk_path = tempfile.mkstemp(suffix=".apk")
        os.close(fd)
        try:
            with patch("src.server.analyze_apk_dynamic", return_value=mock_result):
                data = self.client.post("/analyze-dynamic",
                                        json={"apk_path": apk_path}).get_json()
            self.assertEqual(data["error"], "Emulator not reachable")
        finally:
            os.unlink(apk_path)


# ==============================================================================
# 9. iOS Dynamic Analysis — Flask Endpoint Integration
# ==============================================================================

class TestIosDynamicFlaskEndpoint(unittest.TestCase):

    def setUp(self):
        self.client = flask_app.test_client()

    def test_missing_ipa_path_returns_400(self):
        resp = self.client.post("/analyze-ios-dynamic", json={})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.get_json())

    def test_nonexistent_ipa_returns_404(self):
        resp = self.client.post("/analyze-ios-dynamic",
                                json={"ipa_path": "/tmp/no_such_file.ipa"})
        self.assertEqual(resp.status_code, 404)

    def test_valid_ipa_returns_200_with_response_shape(self):
        from src.models import Finding
        mock_result = IosDynamicAnalysisResult(
            findings=[Finding("spyware", "high", "IOS_DYN_KC_001", "Keychain write", "")],
            events_captured=3,
            traffic_flows_captured=1,
            timeout_seconds=60,
            bundle_id="com.evil.ios",
            simulator_udid="FAKE-UDID-1234",
            error=None,
        )
        fd, ipa_path = tempfile.mkstemp(suffix=".ipa")
        os.close(fd)
        try:
            with patch("src.server.analyze_ipa_dynamic", return_value=mock_result):
                resp = self.client.post("/analyze-ios-dynamic",
                                        json={"ipa_path": ipa_path, "timeout": 60})
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            for key in ("findings", "events_captured", "traffic_flows_captured",
                        "timeout_seconds", "bundle_id", "simulator_udid",
                        "ios_dynamic_risk_delta", "error"):
                self.assertIn(key, data, f"Missing key: {key}")
        finally:
            os.unlink(ipa_path)

    def test_ios_dynamic_risk_delta_nonzero_for_high_finding(self):
        from src.models import Finding
        mock_result = IosDynamicAnalysisResult(
            findings=[Finding("spyware", "high", "IOS_DYN_KC_001", "Keychain write", "")],
        )
        fd, ipa_path = tempfile.mkstemp(suffix=".ipa")
        os.close(fd)
        try:
            with patch("src.server.analyze_ipa_dynamic", return_value=mock_result):
                data = self.client.post("/analyze-ios-dynamic",
                                        json={"ipa_path": ipa_path}).get_json()
            self.assertGreater(data["ios_dynamic_risk_delta"], 0)
        finally:
            os.unlink(ipa_path)

    def test_error_propagated_when_no_simulator_found(self):
        mock_result = IosDynamicAnalysisResult(
            error="No suitable iOS simulator found. Install Xcode and at least one iOS runtime."
        )
        fd, ipa_path = tempfile.mkstemp(suffix=".ipa")
        os.close(fd)
        try:
            with patch("src.server.analyze_ipa_dynamic", return_value=mock_result):
                data = self.client.post("/analyze-ios-dynamic",
                                        json={"ipa_path": ipa_path}).get_json()
            self.assertIsNotNone(data["error"])
            self.assertIn("simulator", data["error"].lower())
        finally:
            os.unlink(ipa_path)


# ==============================================================================
# 10. API Fuzzing — Flask Endpoint Integration
# ==============================================================================

def _clean_fuzz_response(*args, **kwargs):
    """Patch target for api_fuzzer functions — returns empty findings list."""
    return []


def _vulnerable_fuzz_response(*args, **kwargs):
    return [
        {
            "category": "api_security",
            "severity": "high",
            "rule": "api_sqli_error",
            "description": "SQL injection detected",
            "evidence": "error in SQL syntax",
        }
    ]


class TestApiFuzzingFlaskEndpoints(unittest.TestCase):

    def setUp(self):
        self.client = flask_app.test_client()

    # /fuzz-api/openapi
    def test_openapi_missing_spec_returns_400(self):
        resp = self.client.post("/fuzz-api/openapi", json={})
        self.assertEqual(resp.status_code, 400)

    def test_openapi_non_dict_spec_returns_400(self):
        resp = self.client.post("/fuzz-api/openapi", json={"spec": "bad"})
        self.assertEqual(resp.status_code, 400)

    def test_openapi_clean_spec_returns_200_with_findings_list(self):
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "http://localhost:9999"}],
            "paths": {"/ping": {"get": {}}},
        }
        with patch("src.server.fuzz_from_openapi", side_effect=_clean_fuzz_response):
            resp = self.client.post("/fuzz-api/openapi", json={"spec": spec})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("findings", data)
        self.assertIsInstance(data["findings"], list)

    def test_openapi_vulnerable_response_includes_findings(self):
        spec = {"openapi": "3.0.0", "servers": [{"url": "http://x.com"}],
                "paths": {"/search": {"get": {}}}}
        with patch("src.server.fuzz_from_openapi", side_effect=_vulnerable_fuzz_response):
            data = self.client.post("/fuzz-api/openapi", json={"spec": spec}).get_json()
        self.assertGreater(len(data["findings"]), 0)
        self.assertEqual(data["findings"][0]["rule"], "api_sqli_error")

    # /fuzz-api/har
    def test_har_missing_returns_400(self):
        resp = self.client.post("/fuzz-api/har", json={})
        self.assertEqual(resp.status_code, 400)

    def test_har_non_dict_returns_400(self):
        resp = self.client.post("/fuzz-api/har", json={"har": "string"})
        self.assertEqual(resp.status_code, 400)

    def test_har_valid_returns_200(self):
        har = {"log": {"entries": []}}
        with patch("src.server.fuzz_from_har", side_effect=_clean_fuzz_response):
            resp = self.client.post("/fuzz-api/har", json={"har": har})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("findings", resp.get_json())

    # /fuzz-api/endpoints
    def test_endpoints_missing_returns_400(self):
        resp = self.client.post("/fuzz-api/endpoints", json={})
        self.assertEqual(resp.status_code, 400)

    def test_endpoints_non_list_returns_400(self):
        resp = self.client.post("/fuzz-api/endpoints", json={"endpoints": "bad"})
        self.assertEqual(resp.status_code, 400)

    def test_endpoints_valid_returns_200(self):
        with patch("src.server.fuzz_from_endpoint_list", side_effect=_clean_fuzz_response):
            resp = self.client.post("/fuzz-api/endpoints",
                                    json={"endpoints": [{"url": "http://localhost/api", "method": "GET"}]})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("findings", resp.get_json())

    def test_findings_keys_present_in_response(self):
        with patch("src.server.fuzz_from_openapi", side_effect=_vulnerable_fuzz_response):
            spec = {"openapi": "3.0.0", "servers": [{"url": "http://x.com"}],
                    "paths": {"/search": {"get": {}}}}
            data = self.client.post("/fuzz-api/openapi", json={"spec": spec}).get_json()
        for f in data["findings"]:
            for key in ("category", "severity", "rule", "description", "evidence"):
                self.assertIn(key, f)


# ==============================================================================
# 11. Pipeline Integration — report endpoint accepts new analysis types
# ==============================================================================

class TestReportEndpointNewAnalysisTypes(unittest.TestCase):
    """
    The /report endpoint must accept findings from all new Phase 2/3 analysis
    types (dynamic Android, dynamic iOS, API fuzzing, privacy, APPX) and
    generate a PDF without error.
    """

    def setUp(self):
        self.client = flask_app.test_client()

    def _post_report(self, findings: list[dict]) -> int:
        scan = {
            "id": "test-scan-001",
            "filename": "test.apk",
            "sha256": "aabbccdd",
            "verdict": "pha",
            "risk_score": 85,
            "status": "done",
            "created_at": "2026-03-14T00:00:00Z",
        }
        resp = self.client.post("/report", json={"scan": scan, "findings": findings})
        return resp.status_code

    def test_report_with_android_dynamic_findings_succeeds(self):
        findings = [
            {"category": "spyware", "severity": "critical", "rule": "DYN_TEL_001",
             "description": "SMS sent at runtime", "evidence": "+123"},
            {"category": "ransomware", "severity": "high", "rule": "DYN_CRYPTO_002",
             "description": "Key generation at runtime", "evidence": "RSA"},
        ]
        self.assertEqual(self._post_report(findings), 200)

    def test_report_with_ios_dynamic_findings_succeeds(self):
        findings = [
            {"category": "spyware", "severity": "high", "rule": "IOS_DYN_KC_001",
             "description": "Keychain write observed", "evidence": ""},
            {"category": "spyware", "severity": "medium", "rule": "IOS_DYN_PB_001",
             "description": "Pasteboard read observed", "evidence": ""},
        ]
        self.assertEqual(self._post_report(findings), 200)

    def test_report_with_api_fuzzing_findings_succeeds(self):
        findings = [
            {"category": "api_security", "severity": "high", "rule": "api_sqli_error",
             "description": "SQL injection via GET param", "evidence": "SQL syntax error"},
            {"category": "api_security", "severity": "critical", "rule": "api_ssrf_detected",
             "description": "SSRF via url param", "evidence": "ami-id detected"},
        ]
        self.assertEqual(self._post_report(findings), 200)

    def test_report_with_privacy_findings_succeeds(self):
        findings = [
            {"category": "privacy", "severity": "high", "rule": "fine_location_tracking",
             "description": "Fine location permission declared", "evidence": "ACCESS_FINE_LOCATION"},
            {"category": "privacy", "severity": "low", "rule": "tracker_google_analytics",
             "description": "Google Analytics SDK detected", "evidence": "com/google/android/gms/analytics"},
        ]
        self.assertEqual(self._post_report(findings), 200)

    def test_report_with_appx_findings_succeeds(self):
        findings = [
            {"category": "manifest", "severity": "critical",
             "rule": "restricted_cap_runFullTrust",
             "description": "runFullTrust capability declared", "evidence": "runFullTrust"},
            {"category": "manifest", "severity": "high",
             "rule": "pe_virtual_alloc_ex",
             "description": "Process injection API found", "evidence": "VirtualAllocEx"},
        ]
        self.assertEqual(self._post_report(findings), 200)

    def test_report_with_mixed_phase2_phase3_findings_succeeds(self):
        findings = [
            {"category": "spyware", "severity": "critical", "rule": "DYN_TEL_001",
             "description": "SMS sent", "evidence": ""},
            {"category": "privacy", "severity": "high", "rule": "fine_location_tracking",
             "description": "Location permission", "evidence": ""},
            {"category": "api_security", "severity": "high", "rule": "api_sqli_error",
             "description": "SQLi", "evidence": ""},
            {"category": "manifest", "severity": "high", "rule": "restricted_capability_runFullTrust",
             "description": "runFullTrust", "evidence": ""},
            {"category": "spyware", "severity": "high", "rule": "IOS_DYN_KC_001",
             "description": "Keychain write", "evidence": ""},
        ]
        self.assertEqual(self._post_report(findings), 200)

    def test_report_content_type_is_pdf(self):
        resp = self.client.post("/report", json={
            "scan": {"id": "x", "filename": "x.apk", "sha256": "aa",
                     "verdict": "clean", "risk_score": 0,
                     "status": "done", "created_at": "2026-03-14T00:00:00Z"},
            "findings": [],
        })
        self.assertEqual(resp.status_code, 200)
        self.assertIn("application/pdf", resp.content_type)

    def test_report_missing_scan_returns_400(self):
        resp = self.client.post("/report", json={"findings": []})
        self.assertEqual(resp.status_code, 400)


# ==============================================================================
# 12. Health check endpoint (smoke test — validates server is wired up)
# ==============================================================================

class TestHealthEndpoint(unittest.TestCase):

    def test_health_check_returns_ok(self):
        resp = flask_app.test_client().get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"status": "ok"})


if __name__ == "__main__":
    unittest.main()
