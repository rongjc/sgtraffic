"""
Windows APPX/MSIX static analysis module.

Analyzes APPX/MSIX bundles for:
- AppxManifest.xml: identity, capabilities, restricted capabilities, device capabilities
- Insecure API patterns in bundled .dll/.exe binaries (string extraction)
- Dangerous Windows API usage (process injection, crypto, network)
- Certificate/signing validation (AppxSignature.p7x presence and basic checks)
- Known risky capability combinations
"""
import hashlib
import re
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from xml.etree import ElementTree as ET

from .models import Finding


# ---------------------------------------------------------------------------
# Namespace map for AppxManifest.xml
# ---------------------------------------------------------------------------
_NS = {
    "ms":     "http://schemas.microsoft.com/appx/manifest/foundation/windows10",
    "uap":    "http://schemas.microsoft.com/appx/manifest/uap/windows10",
    "rescap": "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities",
    "uap3":   "http://schemas.microsoft.com/appx/manifest/uap/windows10/3",
    "desktop": "http://schemas.microsoft.com/appx/manifest/desktop/windows10",
    "mobile": "http://schemas.microsoft.com/appx/manifest/mobile/windows10",
}

# Restricted capabilities that are high-risk
_HIGH_RISK_RESTRICTED = {
    "runFullTrust":           "App runs with full desktop trust — bypasses UWP sandbox",
    "broadFileSystemAccess":  "Unrestricted file system read/write access",
    "packageManagement":      "Can install/uninstall other packages",
    "allowElevation":         "Can request UAC elevation",
    "interopServices":        "COM/WinRT interop bypassing sandbox",
    "unvirtualizedResources": "Bypasses file-system virtualization",
    "classicAppCompatKey":    "Write access to legacy registry hives",
    "confirmAppClose":        "Can intercept system close events",
}

# Regular capabilities that indicate broad network/privacy access
_SENSITIVE_CAPABILITIES = {
    "privateNetworkClientServer": "Access to private (local) network",
    "enterpriseAuthentication":   "Access to Windows credentials/SSO",
    "sharedUserCertificates":     "Access to shared certificate store",
    "userAccountInformation":     "Access to user account details",
}

# Device capabilities with privacy implications
_SENSITIVE_DEVICE_CAPS = {
    "microphone":  "Microphone access",
    "webcam":      "Camera access",
    "location":    "Precise location access",
    "contacts":    "Contacts access",
    "appointments": "Calendar/appointments access",
    "phoneCall":   "Phone call capability",
    "bluetooth":   "Bluetooth access",
    "radios":      "Radio (Wi-Fi/Bluetooth) control",
    "proximity":   "Near-field proximity sensing",
}

# Dangerous Windows API strings found in PE binaries
_DANGEROUS_APIS: list[tuple[str, str, str]] = [
    # (pattern, rule, description)
    (r"VirtualAllocEx",        "pe_virtual_alloc_ex",      "Process memory injection API (VirtualAllocEx)"),
    (r"WriteProcessMemory",    "pe_write_process_memory",   "Process memory injection API (WriteProcessMemory)"),
    (r"CreateRemoteThread",    "pe_create_remote_thread",   "Remote thread creation — classic code injection"),
    (r"NtCreateThreadEx",      "pe_nt_create_thread_ex",   "Undocumented NT thread API used in shellcode injection"),
    (r"QueueUserAPC",          "pe_queue_user_apc",        "APC injection technique"),
    (r"SetWindowsHookEx",      "pe_set_windows_hook",      "System-wide keyboard/mouse hook"),
    (r"OpenProcess",           "pe_open_process",          "Opens handle to another process — potential injection"),
    (r"NtWriteVirtualMemory",  "pe_nt_write_virtual_memory","Low-level memory write to another process"),
    (r"IsDebuggerPresent",     "pe_anti_debug",            "Anti-debugging check detected"),
    (r"CheckRemoteDebuggerPresent", "pe_anti_debug_remote","Anti-debugging check (remote) detected"),
    (r"ShellExecuteEx?[AW]?",  "pe_shell_execute",         "Arbitrary process/URL launch via ShellExecute"),
    (r"WinExec",               "pe_win_exec",              "Legacy arbitrary process execution (WinExec)"),
    (r"RegSetValueEx[AW]?",    "pe_registry_write",        "Registry write access"),
    (r"RegCreateKeyEx[AW]?",   "pe_registry_create_key",   "Registry key creation"),
    (r"CryptDecrypt",          "pe_crypto_decrypt",        "Decryption API — possible payload unpacking"),
    (r"CryptEncrypt",          "pe_crypto_encrypt",        "Encryption API detected"),
    (r"MD5Init|MD5Update|MD5Final", "pe_weak_hash_md5",   "Weak MD5 hash function detected"),
    (r"http://",               "pe_plaintext_http",        "Plaintext HTTP URL embedded in binary"),
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "pe_hardcoded_ip", "Hardcoded IP address in binary"),
    (r"cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe",
                               "pe_shell_reference",       "Reference to shell interpreter in binary"),
    (r"\\\\\.\\pipe\\",        "pe_named_pipe",            "Named pipe reference — possible lateral movement"),
    (r"SeDebugPrivilege",      "pe_debug_privilege",       "Request for SeDebugPrivilege — process injection enabler"),
]


# ---------------------------------------------------------------------------
# Data model for APPX metadata
# ---------------------------------------------------------------------------

@dataclass
class AppxMetadata:
    platform: str = "Windows"
    sha256: str = ""
    package_name: str = ""
    publisher: str = ""
    version: str = ""
    processor_architecture: str = ""
    capabilities: list[str] = field(default_factory=list)
    restricted_capabilities: list[str] = field(default_factory=list)
    device_capabilities: list[str] = field(default_factory=list)
    signed: bool = False
    publisher_cn: str = ""
    min_windows_version: str = ""
    package_type: str = "appx"  # 'appx' or 'msix'


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze_appx(appx_path: str) -> dict:
    """
    Analyze an APPX or MSIX file and return a JSON-serializable result dict.
    Raises FileNotFoundError if the file doesn't exist.
    """
    path = Path(appx_path)
    if not path.exists():
        raise FileNotFoundError(f"APPX/MSIX not found: {appx_path}")

    ext = path.suffix.lower()
    sha256 = _sha256(appx_path)
    findings: list[Finding] = []
    metadata = AppxMetadata(
        sha256=sha256,
        package_type="msix" if ext == ".msix" else "appx",
    )

    with zipfile.ZipFile(appx_path, "r") as zf:
        names = zf.namelist()

        # 1. Parse AppxManifest.xml
        manifest_xml = _load_manifest(zf, names)
        if manifest_xml is not None:
            _populate_metadata(metadata, manifest_xml)
            findings.extend(_analyze_manifest(metadata))
        else:
            findings.append(Finding(
                category="manifest",
                severity="high",
                rule="missing_manifest",
                description="AppxManifest.xml not found in package",
                evidence="",
            ))

        # 2. Check signing
        signing_findings = _check_signing(zf, names, metadata)
        findings.extend(signing_findings)

        # 3. Scan PE binaries (dll/exe) for dangerous API strings
        pe_findings = _scan_pe_binaries(zf, names)
        findings.extend(pe_findings)

    # Compute risk score and verdict
    risk_score, verdict = _compute_risk(findings)

    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "pha_categories": [],
        "findings": [
            {
                "category": f.category,
                "severity": f.severity,
                "rule": f.rule,
                "description": f.description,
                "evidence": f.evidence,
            }
            for f in findings
        ],
        "metadata": {
            "platform": metadata.platform,
            "sha256": metadata.sha256,
            "package_name": metadata.package_name,
            "publisher": metadata.publisher,
            "version": metadata.version,
            "processor_architecture": metadata.processor_architecture,
            "capabilities": metadata.capabilities,
            "restricted_capabilities": metadata.restricted_capabilities,
            "device_capabilities": metadata.device_capabilities,
            "signed": metadata.signed,
            "publisher_cn": metadata.publisher_cn,
            "min_windows_version": metadata.min_windows_version,
            "package_type": metadata.package_type,
        },
    }


# ---------------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------------

def _load_manifest(zf: zipfile.ZipFile, names: list[str]) -> Optional[ET.Element]:
    """Locate and parse AppxManifest.xml from the ZIP."""
    candidates = [n for n in names if n.lower() in ("appxmanifest.xml", "appxmanifest.xml/")]
    if not candidates:
        # Also try in bundle root for MSIX bundles
        candidates = [n for n in names if n.lower().endswith("appxmanifest.xml")]
    if not candidates:
        return None
    try:
        data = zf.read(candidates[0])
        return ET.fromstring(data)
    except Exception:
        return None


def _populate_metadata(metadata: AppxMetadata, root: ET.Element) -> None:
    """Extract identity and capability info from the manifest root element."""
    # Identity element — try namespaced first, then plain fallback
    identity = root.find("ms:Identity", _NS)
    if identity is None:
        identity = root.find(
            "{http://schemas.microsoft.com/appx/manifest/foundation/windows10}Identity"
        )
    if identity is None:
        identity = root.find("Identity")
    if identity is not None:
        metadata.package_name = identity.get("Name", "")
        metadata.publisher = identity.get("Publisher", "")
        metadata.version = identity.get("Version", "")
        metadata.processor_architecture = identity.get("ProcessorArchitecture", "neutral")

        # Extract CN from publisher string
        cn_match = re.search(r"CN=([^,]+)", metadata.publisher)
        if cn_match:
            metadata.publisher_cn = cn_match.group(1).strip()

    # Capabilities — collect all variants
    caps_root = _find_element(root, "Capabilities")
    if caps_root is not None:
        for child in caps_root:
            tag_local = _local_name(child.tag)
            name = child.get("Name", "")
            if not name:
                continue
            ns = child.tag.split("}")[0].lstrip("{") if "}" in child.tag else ""
            if "restrictedcapabilities" in ns or tag_local.lower() in ("capability",) and "rescap" in ns:
                metadata.restricted_capabilities.append(name)
            elif tag_local.lower() == "devicecapability":
                metadata.device_capabilities.append(name)
            elif tag_local.lower() == "capability":
                metadata.capabilities.append(name)

    # TargetDeviceFamily / minimum Windows version
    tdf = _find_element(root, "TargetDeviceFamily")
    if tdf is not None:
        metadata.min_windows_version = tdf.get("MinVersion", "")


def _find_element(root: ET.Element, local_name: str) -> Optional[ET.Element]:
    """Find a child element by local name, ignoring namespace."""
    for child in root.iter():
        if _local_name(child.tag) == local_name:
            return child
    return None


def _local_name(tag: str) -> str:
    return tag.split("}")[-1] if "}" in tag else tag


# ---------------------------------------------------------------------------
# Manifest analysis — findings
# ---------------------------------------------------------------------------

def _analyze_manifest(metadata: AppxMetadata) -> list[Finding]:
    findings: list[Finding] = []

    # Restricted capabilities
    for cap in metadata.restricted_capabilities:
        desc = _HIGH_RISK_RESTRICTED.get(cap, f"Restricted capability declared: {cap}")
        severity = "critical" if cap in ("runFullTrust", "allowElevation", "broadFileSystemAccess") else "high"
        findings.append(Finding(
            category="capabilities",
            severity=severity,
            rule=f"restricted_cap_{cap}",
            description=desc,
            evidence=f"<rescap:Capability Name=\"{cap}\"/>",
        ))

    # Sensitive standard capabilities
    for cap in metadata.capabilities:
        if cap in _SENSITIVE_CAPABILITIES:
            findings.append(Finding(
                category="capabilities",
                severity="medium",
                rule=f"sensitive_cap_{cap}",
                description=_SENSITIVE_CAPABILITIES[cap],
                evidence=f"<Capability Name=\"{cap}\"/>",
            ))

    # Device capabilities
    for cap in metadata.device_capabilities:
        if cap in _SENSITIVE_DEVICE_CAPS:
            findings.append(Finding(
                category="capabilities",
                severity="medium",
                rule=f"device_cap_{cap}",
                description=f"Device capability: {_SENSITIVE_DEVICE_CAPS[cap]}",
                evidence=f"<DeviceCapability Name=\"{cap}\"/>",
            ))

    # runFullTrust combined with network — high exfiltration risk
    has_network = "internetClient" in metadata.capabilities or "internetClientServer" in metadata.capabilities
    has_full_trust = "runFullTrust" in metadata.restricted_capabilities
    if has_full_trust and has_network:
        findings.append(Finding(
            category="capabilities",
            severity="critical",
            rule="full_trust_with_network",
            description="Full trust execution combined with internet access — high exfiltration/C2 risk",
            evidence=f"runFullTrust + network capability",
        ))

    # No package name
    if not metadata.package_name:
        findings.append(Finding(
            category="manifest",
            severity="medium",
            rule="missing_identity_name",
            description="Package Identity Name is missing or empty",
            evidence="",
        ))

    return findings


# ---------------------------------------------------------------------------
# Signing analysis
# ---------------------------------------------------------------------------

def _check_signing(
    zf: zipfile.ZipFile, names: list[str], metadata: AppxMetadata
) -> list[Finding]:
    findings: list[Finding] = []
    sig_file = next(
        (n for n in names if n.lower() in ("appxsignature.p7x", "appxblockhashlist.xml")), None
    )

    if sig_file:
        metadata.signed = True
        # Basic heuristic: check if publisher is Microsoft or a known trusted signer
        publisher_cn = metadata.publisher_cn.lower()
        if publisher_cn in ("", "unknown"):
            findings.append(Finding(
                category="certificate",
                severity="medium",
                rule="unknown_publisher",
                description="Package is signed but publisher CN could not be determined",
                evidence=metadata.publisher,
            ))
        elif publisher_cn == "test":
            findings.append(Finding(
                category="certificate",
                severity="high",
                rule="test_signed",
                description="Package appears to be test-signed (Publisher CN='test')",
                evidence=metadata.publisher,
            ))
    else:
        metadata.signed = False
        findings.append(Finding(
            category="certificate",
            severity="high",
            rule="unsigned_package",
            description="No AppxSignature.p7x found — package may be unsigned or signature stripped",
            evidence="AppxSignature.p7x not found in bundle",
        ))

    return findings


# ---------------------------------------------------------------------------
# PE binary scanning (string extraction)
# ---------------------------------------------------------------------------

def _scan_pe_binaries(zf: zipfile.ZipFile, names: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    pe_files = [n for n in names if n.lower().endswith((".dll", ".exe"))]

    for pe_name in pe_files[:20]:  # cap at 20 binaries to bound execution time
        try:
            data = zf.read(pe_name)
        except Exception:
            continue

        if not _is_pe(data):
            continue

        strings = _extract_strings(data, min_len=5)
        joined = "\n".join(strings)

        seen_rules: set[str] = set()
        for pattern, rule, description in _DANGEROUS_APIS:
            if rule in seen_rules:
                continue
            match = re.search(pattern, joined, re.IGNORECASE)
            if match:
                seen_rules.add(rule)
                # Find the line containing the match for evidence
                evidence_line = next(
                    (s for s in strings if re.search(pattern, s, re.IGNORECASE)), match.group(0)
                )
                findings.append(Finding(
                    category="binary_analysis",
                    severity=_pe_rule_severity(rule),
                    rule=rule,
                    description=f"{description} (found in {pe_name})",
                    evidence=evidence_line[:200],
                ))

    return findings


def _is_pe(data: bytes) -> bool:
    """Check MZ magic bytes for PE format."""
    return len(data) >= 2 and data[:2] == b"MZ"


def _extract_strings(data: bytes, min_len: int = 5) -> list[str]:
    """Extract printable ASCII strings from binary data."""
    result = []
    pattern = re.compile(rb"[ -~]{%d,}" % min_len)
    for match in pattern.finditer(data):
        try:
            result.append(match.group(0).decode("ascii", errors="ignore"))
        except Exception:
            pass
    return result


def _pe_rule_severity(rule: str) -> str:
    critical_rules = {
        "pe_virtual_alloc_ex", "pe_write_process_memory", "pe_create_remote_thread",
        "pe_nt_create_thread_ex", "pe_queue_user_apc", "pe_nt_write_virtual_memory",
        "pe_debug_privilege",
    }
    high_rules = {
        "pe_shell_execute", "pe_win_exec", "pe_set_windows_hook", "pe_open_process",
        "pe_anti_debug", "pe_anti_debug_remote", "pe_named_pipe",
    }
    if rule in critical_rules:
        return "critical"
    if rule in high_rules:
        return "high"
    return "medium"


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS = {"critical": 30, "high": 15, "medium": 5, "low": 1}


def _compute_risk(findings: list[Finding]) -> tuple[int, str]:
    score = min(100, sum(_SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings))
    verdict: str
    if score >= 60:
        verdict = "pha"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "clean"
    return score, verdict


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _sha256(file_path: str) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
