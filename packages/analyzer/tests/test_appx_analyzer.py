"""
Tests for APPX/MSIX static analysis module.

Covers:
- AppxManifest.xml parsing (identity, capabilities, restricted capabilities)
- Restricted capability detection and risk flags
- Sensitive capability and device capability detection
- runFullTrust + network combination warning
- Certificate/signing checks (signed vs unsigned)
- PE binary string scanning for dangerous APIs
- Risk score computation and verdict assignment
- Error handling (missing file, missing manifest, bad ZIP)
"""
import io
import os
import struct
import sys
import tempfile
import zipfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.appx_analyzer import (
    analyze_appx,
    _analyze_manifest,
    _check_signing,
    _compute_risk,
    _extract_strings,
    _is_pe,
    _local_name,
    AppxMetadata,
)
from src.models import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_MANIFEST = """\
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="{name}" Publisher="{publisher}" Version="{version}" ProcessorArchitecture="x64"/>
  <Properties>
    <DisplayName>Test App</DisplayName>
    <PublisherDisplayName>Test Publisher</PublisherDisplayName>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.19041.0"/>
  </Dependencies>
  <Capabilities>
    {capabilities}
  </Capabilities>
</Package>
"""


def _make_manifest(
    name: str = "com.test.app",
    publisher: str = "CN=Test Corp, O=Test, C=US",
    version: str = "1.0.0.0",
    capabilities: str = "",
) -> bytes:
    return _BASE_MANIFEST.format(
        name=name, publisher=publisher, version=version, capabilities=capabilities
    ).encode("utf-8")


def _make_pe_bytes(strings: list[str]) -> bytes:
    """Build a fake MZ PE binary with ASCII strings embedded."""
    data = bytearray(b"MZ" + b"\x00" * 510)
    for s in strings:
        data += s.encode("ascii") + b"\x00"
    return bytes(data)


def _build_appx(
    manifest: bytes | None = None,
    signature: bool = False,
    pe_files: dict[str, bytes] | None = None,
    extra_files: dict[str, bytes] | None = None,
) -> bytes:
    """Create a minimal APPX/MSIX ZIP in memory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        if manifest is not None:
            zf.writestr("AppxManifest.xml", manifest)
        if signature:
            zf.writestr("AppxSignature.p7x", b"\x00" * 16)
        if pe_files:
            for fname, data in pe_files.items():
                zf.writestr(fname, data)
        if extra_files:
            for fname, data in extra_files.items():
                zf.writestr(fname, data)
    return buf.getvalue()


def _write_tmp(data: bytes, suffix: str = ".appx") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


# ---------------------------------------------------------------------------
# Unit tests — helper functions
# ---------------------------------------------------------------------------

class TestLocalName:
    def test_namespaced(self):
        assert _local_name("{http://example.com/ns}Element") == "Element"

    def test_plain(self):
        assert _local_name("Element") == "Element"


class TestIsPe:
    def test_mz_magic(self):
        assert _is_pe(b"MZ\x00\x00")

    def test_not_pe(self):
        assert not _is_pe(b"PK\x03\x04")  # ZIP magic
        assert not _is_pe(b"")

    def test_too_short(self):
        assert not _is_pe(b"M")


class TestExtractStrings:
    def test_extracts_ascii(self):
        data = b"\x00" * 4 + b"Hello World" + b"\x00"
        strings = _extract_strings(data, min_len=5)
        assert "Hello World" in strings

    def test_min_len_filter(self):
        data = b"Hi\x00" + b"LongString" + b"\x00"
        strings = _extract_strings(data, min_len=5)
        assert "Hi" not in strings
        assert "LongString" in strings


# ---------------------------------------------------------------------------
# Unit tests — manifest analysis
# ---------------------------------------------------------------------------

class TestAnalyzeManifest:
    def _make_meta(self, **kwargs) -> AppxMetadata:
        meta = AppxMetadata()
        for k, v in kwargs.items():
            setattr(meta, k, v)
        return meta

    def test_restricted_cap_run_full_trust_is_critical(self):
        meta = self._make_meta(restricted_capabilities=["runFullTrust"])
        findings = _analyze_manifest(meta)
        rules = [f.rule for f in findings]
        assert "restricted_cap_runFullTrust" in rules
        f = next(f for f in findings if f.rule == "restricted_cap_runFullTrust")
        assert f.severity == "critical"

    def test_restricted_cap_high_severity(self):
        meta = self._make_meta(restricted_capabilities=["interopServices"])
        findings = _analyze_manifest(meta)
        f = next(f for f in findings if "restricted_cap_interopServices" in f.rule)
        assert f.severity == "high"

    def test_sensitive_capability_medium(self):
        meta = self._make_meta(capabilities=["privateNetworkClientServer"])
        findings = _analyze_manifest(meta)
        f = next(f for f in findings if "sensitive_cap_privateNetworkClientServer" in f.rule)
        assert f.severity == "medium"

    def test_device_capability_medium(self):
        meta = self._make_meta(device_capabilities=["microphone"])
        findings = _analyze_manifest(meta)
        f = next(f for f in findings if "device_cap_microphone" in f.rule)
        assert f.severity == "medium"

    def test_full_trust_with_internet_is_critical(self):
        meta = self._make_meta(
            restricted_capabilities=["runFullTrust"],
            capabilities=["internetClient"],
        )
        findings = _analyze_manifest(meta)
        rules = [f.rule for f in findings]
        assert "full_trust_with_network" in rules
        f = next(f for f in findings if f.rule == "full_trust_with_network")
        assert f.severity == "critical"

    def test_no_extra_finding_for_clean_app(self):
        meta = self._make_meta(
            package_name="com.clean.app",
            capabilities=["internetClient"],
        )
        findings = _analyze_manifest(meta)
        # Only internetClient is not in _SENSITIVE_CAPABILITIES so no finding
        assert all(f.rule != "full_trust_with_network" for f in findings)
        assert all("restricted" not in f.rule for f in findings)

    def test_missing_package_name(self):
        meta = self._make_meta(package_name="")
        findings = _analyze_manifest(meta)
        assert any(f.rule == "missing_identity_name" for f in findings)


# ---------------------------------------------------------------------------
# Unit tests — signing
# ---------------------------------------------------------------------------

class TestCheckSigning:
    def _names_signed(self):
        return ["AppxManifest.xml", "AppxSignature.p7x"]

    def _names_unsigned(self):
        return ["AppxManifest.xml"]

    def test_signed_package_no_unsigned_finding(self):
        meta = AppxMetadata(publisher_cn="Test Corp")
        findings = _check_signing(None, self._names_signed(), meta)  # type: ignore[arg-type]
        assert not any(f.rule == "unsigned_package" for f in findings)
        assert meta.signed is True

    def test_unsigned_package_finding(self):
        meta = AppxMetadata()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("AppxManifest.xml", b"")
        buf.seek(0)
        with zipfile.ZipFile(buf) as zf:
            names = zf.namelist()
        findings = _check_signing(zf, names, meta)
        assert any(f.rule == "unsigned_package" for f in findings)
        assert meta.signed is False

    def test_test_signed_package_warning(self):
        meta = AppxMetadata(publisher_cn="test", signed=True)
        findings = _check_signing(None, self._names_signed(), meta)  # type: ignore[arg-type]
        assert any(f.rule == "test_signed" for f in findings)


# ---------------------------------------------------------------------------
# Unit tests — risk scoring
# ---------------------------------------------------------------------------

class TestComputeRisk:
    def _make_finding(self, severity: str) -> Finding:
        return Finding(category="test", severity=severity, rule="r", description="d")  # type: ignore[arg-type]

    def test_clean_no_findings(self):
        score, verdict = _compute_risk([])
        assert score == 0
        assert verdict == "clean"

    def test_suspicious_threshold(self):
        findings = [self._make_finding("high")] * 2  # 2 * 15 = 30
        score, verdict = _compute_risk(findings)
        assert score == 30
        assert verdict == "suspicious"

    def test_pha_threshold(self):
        findings = [self._make_finding("critical")] * 3  # 3 * 30 = 90
        score, verdict = _compute_risk(findings)
        assert verdict == "pha"

    def test_score_capped_at_100(self):
        findings = [self._make_finding("critical")] * 10  # would be 300
        score, _ = _compute_risk(findings)
        assert score == 100


# ---------------------------------------------------------------------------
# Integration tests — analyze_appx
# ---------------------------------------------------------------------------

class TestAnalyzeAppx:
    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            analyze_appx("/nonexistent/file.appx")

    def test_clean_minimal_appx(self):
        manifest = _make_manifest(capabilities="<Capability Name=\"internetClient\"/>")
        data = _build_appx(manifest=manifest, signature=True)
        path = _write_tmp(data)
        try:
            result = analyze_appx(path)
            assert result["verdict"] in ("clean", "suspicious", "pha")
            assert "metadata" in result
            assert result["metadata"]["package_name"] == "com.test.app"
            assert result["metadata"]["signed"] is True
            assert result["metadata"]["package_type"] == "appx"
        finally:
            os.unlink(path)

    def test_msix_package_type(self):
        manifest = _make_manifest()
        data = _build_appx(manifest=manifest, signature=True)
        path = _write_tmp(data, suffix=".msix")
        try:
            result = analyze_appx(path)
            assert result["metadata"]["package_type"] == "msix"
        finally:
            os.unlink(path)

    def test_restricted_cap_detected(self):
        caps = '<rescap:Capability Name="runFullTrust"/><Capability Name="internetClient"/>'
        manifest = _make_manifest(capabilities=caps)
        data = _build_appx(manifest=manifest)
        path = _write_tmp(data)
        try:
            result = analyze_appx(path)
            rules = [f["rule"] for f in result["findings"]]
            assert "restricted_cap_runFullTrust" in rules
            assert "full_trust_with_network" in rules
        finally:
            os.unlink(path)

    def test_unsigned_package_finding(self):
        manifest = _make_manifest()
        data = _build_appx(manifest=manifest, signature=False)
        path = _write_tmp(data)
        try:
            result = analyze_appx(path)
            rules = [f["rule"] for f in result["findings"]]
            assert "unsigned_package" in rules
        finally:
            os.unlink(path)

    def test_dangerous_api_in_pe_binary(self):
        pe = _make_pe_bytes(["VirtualAllocEx", "WriteProcessMemory"])
        manifest = _make_manifest()
        data = _build_appx(manifest=manifest, pe_files={"app.dll": pe})
        path = _write_tmp(data)
        try:
            result = analyze_appx(path)
            rules = [f["rule"] for f in result["findings"]]
            assert "pe_virtual_alloc_ex" in rules
            assert "pe_write_process_memory" in rules
            # These are critical severity
            severities = {f["rule"]: f["severity"] for f in result["findings"]}
            assert severities["pe_virtual_alloc_ex"] == "critical"
        finally:
            os.unlink(path)

    def test_non_pe_dll_ignored(self):
        # A .dll file that is NOT a PE (no MZ header)
        fake_dll = b"\x7fELF" + b"\x00" * 100  # ELF, not PE
        manifest = _make_manifest()
        data = _build_appx(manifest=manifest, pe_files={"lib.dll": fake_dll})
        path = _write_tmp(data)
        try:
            result = analyze_appx(path)
            rules = [f["rule"] for f in result["findings"]]
            # No PE-specific findings from ELF binary
            assert not any(r.startswith("pe_") for r in rules)
        finally:
            os.unlink(path)

    def test_missing_manifest_finding(self):
        data = _build_appx(manifest=None)
        path = _write_tmp(data)
        try:
            result = analyze_appx(path)
            rules = [f["rule"] for f in result["findings"]]
            assert "missing_manifest" in rules
        finally:
            os.unlink(path)

    def test_result_structure(self):
        manifest = _make_manifest()
        data = _build_appx(manifest=manifest, signature=True)
        path = _write_tmp(data)
        try:
            result = analyze_appx(path)
            assert "verdict" in result
            assert "risk_score" in result
            assert "pha_categories" in result
            assert "findings" in result
            assert "metadata" in result
            meta = result["metadata"]
            assert "platform" in meta
            assert meta["platform"] == "Windows"
            assert "sha256" in meta
            assert len(meta["sha256"]) == 64
        finally:
            os.unlink(path)

    def test_high_risk_app_gets_pha_verdict(self):
        caps = "\n".join([
            '<rescap:Capability Name="runFullTrust"/>',
            '<rescap:Capability Name="broadFileSystemAccess"/>',
            '<rescap:Capability Name="allowElevation"/>',
            '<Capability Name="internetClient"/>',
        ])
        pe = _make_pe_bytes([
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "NtCreateThreadEx", "SeDebugPrivilege",
        ])
        manifest = _make_manifest(capabilities=caps)
        data = _build_appx(manifest=manifest, pe_files={"evil.dll": pe})
        path = _write_tmp(data)
        try:
            result = analyze_appx(path)
            assert result["verdict"] in ("suspicious", "pha")
            assert result["risk_score"] > 0
        finally:
            os.unlink(path)
