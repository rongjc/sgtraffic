"""
iOS IPA static analysis module.

Analyzes IPA bundles for:
- Info.plist misconfigurations (ATS, URL schemes, privacy keys)
- Entitlement abuse (debug, private entitlements)
- Insecure API patterns in Mach-O binaries (string extraction)
- Known tracker/ad SDK framework fingerprints
- Provisioning profile metadata
"""
import hashlib
import io
import plistlib
import re
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .models import AnalysisResult, Finding


# ---------------------------------------------------------------------------
# Data model for IPA metadata
# ---------------------------------------------------------------------------

@dataclass
class IpaMetadata:
    bundle_id: str = ""
    bundle_name: str = ""
    version: str = ""
    min_os_version: str = ""
    platform: str = "iOS"
    sha256: str = ""
    entitlements: dict = field(default_factory=dict)
    url_schemes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze_ipa(ipa_path: str) -> dict:
    """
    Analyze an IPA file and return a JSON-serializable result dict.
    Raises FileNotFoundError if the file doesn't exist.
    """
    path = Path(ipa_path)
    if not path.exists():
        raise FileNotFoundError(f"IPA not found: {ipa_path}")

    sha256 = _sha256(ipa_path)
    findings: list[Finding] = []
    metadata = IpaMetadata(sha256=sha256)

    try:
        with zipfile.ZipFile(ipa_path, "r") as zf:
            names = zf.namelist()

            # Locate the .app bundle inside Payload/
            app_dir = _find_app_dir(names)

            # 1. Info.plist analysis
            info_plist = _load_plist(zf, app_dir, "Info.plist")
            if info_plist:
                _populate_metadata(metadata, info_plist)
                findings.extend(_analyze_info_plist(info_plist))

            # 2. Entitlements analysis (embedded in binary or .xcent file)
            entitlements = _extract_entitlements(zf, names, app_dir)
            if entitlements:
                metadata.entitlements = entitlements
                findings.extend(_analyze_entitlements(entitlements))

            # 3. Binary string analysis (Mach-O)
            binary_path = _find_main_binary(zf, names, app_dir, info_plist)
            if binary_path:
                binary_data = zf.read(binary_path)
                binary_strings = _extract_strings(binary_data)
                findings.extend(_analyze_binary_strings(binary_strings))

            # 4. Tracker/SDK detection via framework directory
            findings.extend(_detect_trackers(names, app_dir))

            # 5. Provisioning profile metadata check
            provision_path = _find_file(names, app_dir, "embedded.mobileprovision")
            if provision_path:
                findings.extend(_analyze_provisioning_profile(zf, provision_path))

    except zipfile.BadZipFile:
        findings.append(Finding(
            category="non_android_threat",
            severity="medium",
            rule="ipa_parse_error",
            description="IPA file could not be opened as a ZIP archive — may be corrupted or obfuscated.",
            evidence=ipa_path,
        ))

    risk_score = _compute_risk_score(findings)
    pha_categories = list({f.category for f in findings})
    verdict = _determine_verdict(risk_score, pha_categories)

    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "pha_categories": pha_categories,
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
            "bundle_id": metadata.bundle_id,
            "bundle_name": metadata.bundle_name,
            "version": metadata.version,
            "min_os_version": metadata.min_os_version,
            "platform": metadata.platform,
            "sha256": metadata.sha256,
            "url_schemes": metadata.url_schemes,
        },
    }


# ---------------------------------------------------------------------------
# ZIP / bundle helpers
# ---------------------------------------------------------------------------

def _find_app_dir(names: list[str]) -> str:
    """Return the Payload/<App>.app/ prefix, or empty string."""
    for name in names:
        parts = name.split("/")
        if len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app"):
            return f"Payload/{parts[1]}/"
    return ""


def _find_file(names: list[str], app_dir: str, filename: str) -> Optional[str]:
    """Return the zip path for a file directly inside app_dir, or None."""
    target = f"{app_dir}{filename}"
    if target in names:
        return target
    # Case-insensitive fallback
    lower = filename.lower()
    for n in names:
        if n.lower() == target.lower():
            return n
    return None


def _load_plist(zf: zipfile.ZipFile, app_dir: str, filename: str) -> Optional[dict]:
    """Load and parse a plist file from the ZIP, returning a dict or None."""
    path = _find_file(zf.namelist(), app_dir, filename)
    if not path:
        return None
    try:
        data = zf.read(path)
        return plistlib.loads(data)
    except Exception:
        return None


def _find_main_binary(
    zf: zipfile.ZipFile,
    names: list[str],
    app_dir: str,
    info_plist: Optional[dict],
) -> Optional[str]:
    """Locate the main Mach-O binary inside the app bundle."""
    if info_plist:
        exe_name = info_plist.get("CFBundleExecutable", "")
        if exe_name:
            candidate = f"{app_dir}{exe_name}"
            if candidate in names:
                return candidate

    # Fallback: pick the largest file directly inside app_dir (likely the binary)
    candidates = [
        n for n in names
        if n.startswith(app_dir)
        and "/" not in n[len(app_dir):]
        and not n.endswith("/")
        and not n.endswith(".plist")
        and not n.endswith(".nib")
        and not n.endswith(".png")
        and not n.endswith(".json")
    ]
    if not candidates:
        return None

    # Verify it looks like a Mach-O (magic bytes)
    for c in candidates:
        try:
            header = zf.read(c)[:4]
            if _is_macho(header):
                return c
        except Exception:
            pass
    return candidates[0] if candidates else None


def _is_macho(header: bytes) -> bool:
    """Check for Mach-O magic bytes (32/64-bit, fat binary, both endians)."""
    if len(header) < 4:
        return False
    magic = struct.unpack(">I", header[:4])[0]
    return magic in (
        0xFEEDFACE,  # 32-bit little-endian
        0xCEFAEDFE,  # 32-bit big-endian
        0xFEEDFACF,  # 64-bit little-endian
        0xCFFAEDFE,  # 64-bit big-endian
        0xCAFEBABE,  # Fat binary (universal)
        0xBEBAFECA,  # Fat binary (reversed)
    )


# ---------------------------------------------------------------------------
# Metadata extraction
# ---------------------------------------------------------------------------

def _populate_metadata(metadata: IpaMetadata, info_plist: dict) -> None:
    metadata.bundle_id = str(info_plist.get("CFBundleIdentifier", ""))
    metadata.bundle_name = str(info_plist.get("CFBundleDisplayName") or info_plist.get("CFBundleName", ""))
    metadata.version = str(info_plist.get("CFBundleShortVersionString") or info_plist.get("CFBundleVersion", ""))
    metadata.min_os_version = str(info_plist.get("MinimumOSVersion", ""))

    # URL schemes
    url_types = info_plist.get("CFBundleURLTypes", [])
    if isinstance(url_types, list):
        for url_type in url_types:
            if isinstance(url_type, dict):
                schemes = url_type.get("CFBundleURLSchemes", [])
                if isinstance(schemes, list):
                    metadata.url_schemes.extend(str(s) for s in schemes)


# ---------------------------------------------------------------------------
# Info.plist analysis
# ---------------------------------------------------------------------------

def _analyze_info_plist(plist: dict) -> list[Finding]:
    findings: list[Finding] = []

    findings.extend(_check_ats(plist))
    findings.extend(_check_url_schemes(plist))
    findings.extend(_check_file_sharing(plist))
    findings.extend(_check_privacy_descriptions(plist))
    findings.extend(_check_queried_schemes(plist))

    return findings


def _check_ats(plist: dict) -> list[Finding]:
    """Detect App Transport Security (ATS) misconfigurations."""
    findings = []
    ats = plist.get("NSAppTransportSecurity")
    if not isinstance(ats, dict):
        return findings

    if ats.get("NSAllowsArbitraryLoads") is True:
        findings.append(Finding(
            category="data_collection",
            severity="high",
            rule="ats_allows_arbitrary_loads",
            description="NSAllowsArbitraryLoads is true — ATS is fully disabled, allowing cleartext HTTP traffic to any host.",
            evidence="NSAppTransportSecurity.NSAllowsArbitraryLoads = true",
        ))

    if ats.get("NSAllowsArbitraryLoadsForMedia") is True:
        findings.append(Finding(
            category="data_collection",
            severity="medium",
            rule="ats_allows_arbitrary_loads_media",
            description="NSAllowsArbitraryLoadsForMedia is true — ATS disabled for media connections.",
            evidence="NSAppTransportSecurity.NSAllowsArbitraryLoadsForMedia = true",
        ))

    if ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
        findings.append(Finding(
            category="data_collection",
            severity="medium",
            rule="ats_allows_arbitrary_loads_web",
            description="NSAllowsArbitraryLoadsInWebContent is true — ATS disabled in WebViews.",
            evidence="NSAppTransportSecurity.NSAllowsArbitraryLoadsInWebContent = true",
        ))

    if ats.get("NSAllowsLocalNetworking") is True:
        findings.append(Finding(
            category="data_collection",
            severity="low",
            rule="ats_allows_local_networking",
            description="NSAllowsLocalNetworking is true — allows cleartext connections to local network hosts.",
            evidence="NSAppTransportSecurity.NSAllowsLocalNetworking = true",
        ))

    # Per-domain exceptions
    exception_domains = ats.get("NSExceptionDomains", {})
    if isinstance(exception_domains, dict):
        insecure_domains = []
        for domain, config in exception_domains.items():
            if isinstance(config, dict):
                if config.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                    insecure_domains.append(domain)
                if config.get("NSIncludesSubdomains") is True and config.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                    # Already caught above, skip duplicate
                    pass
        if insecure_domains:
            findings.append(Finding(
                category="data_collection",
                severity="medium",
                rule="ats_insecure_exception_domains",
                description="ATS exception domains allow insecure HTTP loads for specific hosts.",
                evidence=f"Insecure domains: {', '.join(insecure_domains[:5])}",
            ))

    return findings


def _check_url_schemes(plist: dict) -> list[Finding]:
    """Detect insecure or suspicious custom URL schemes."""
    findings = []
    url_types = plist.get("CFBundleURLTypes", [])
    if not isinstance(url_types, list):
        return findings

    all_schemes = []
    for url_type in url_types:
        if isinstance(url_type, dict):
            schemes = url_type.get("CFBundleURLSchemes", [])
            if isinstance(schemes, list):
                all_schemes.extend(str(s).lower() for s in schemes)

    # http/https as a custom URL scheme is unusual (hijacking)
    if "http" in all_schemes or "https" in all_schemes:
        findings.append(Finding(
            category="phishing",
            severity="high",
            rule="url_scheme_hijack_http",
            description="App registers 'http' or 'https' as a custom URL scheme — potential URL scheme hijacking for phishing.",
            evidence=f"URL schemes: {', '.join(all_schemes)}",
        ))

    return findings


def _check_file_sharing(plist: dict) -> list[Finding]:
    """Detect file sharing / document access flags that leak user data."""
    findings = []

    if plist.get("UIFileSharingEnabled") is True:
        findings.append(Finding(
            category="data_collection",
            severity="medium",
            rule="file_sharing_enabled",
            description="UIFileSharingEnabled is true — app's Documents folder is accessible via iTunes file sharing.",
            evidence="UIFileSharingEnabled = true",
        ))

    if plist.get("LSSupportsOpeningDocumentsInPlace") is True:
        findings.append(Finding(
            category="data_collection",
            severity="low",
            rule="documents_in_place",
            description="LSSupportsOpeningDocumentsInPlace is true — app can open documents in place, exposing file paths.",
            evidence="LSSupportsOpeningDocumentsInPlace = true",
        ))

    return findings


_PRIVACY_KEYS = {
    "NSCameraUsageDescription": "camera access",
    "NSMicrophoneUsageDescription": "microphone access",
    "NSLocationAlwaysUsageDescription": "always-on location",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "always-on location",
    "NSLocationWhenInUseUsageDescription": "location when in use",
    "NSContactsUsageDescription": "contacts access",
    "NSPhotoLibraryUsageDescription": "photo library access",
    "NSCalendarsUsageDescription": "calendar access",
    "NSRemindersUsageDescription": "reminders access",
    "NSMotionUsageDescription": "motion/activity data",
    "NSHealthShareUsageDescription": "HealthKit read access",
    "NSHealthUpdateUsageDescription": "HealthKit write access",
}


def _check_privacy_descriptions(plist: dict) -> list[Finding]:
    """Flag apps that request sensitive permissions but provide empty/missing descriptions."""
    findings = []
    suspicious = []
    for key, desc in _PRIVACY_KEYS.items():
        if key in plist:
            value = plist[key]
            # Empty or very short description is suspicious
            if not value or (isinstance(value, str) and len(value.strip()) < 5):
                suspicious.append(f"{key} ({desc})")

    if suspicious:
        findings.append(Finding(
            category="data_collection",
            severity="low",
            rule="empty_privacy_description",
            description="App requests sensitive permissions but provides empty or meaningless usage descriptions — may hide true data collection intent.",
            evidence="; ".join(suspicious[:5]),
        ))

    return findings


def _check_queried_schemes(plist: dict) -> list[Finding]:
    """Detect apps querying many URL schemes (device fingerprinting)."""
    findings = []
    queried = plist.get("LSApplicationQueriesSchemes", [])
    if isinstance(queried, list) and len(queried) > 20:
        findings.append(Finding(
            category="data_collection",
            severity="medium",
            rule="excessive_url_scheme_queries",
            description=f"App queries {len(queried)} URL schemes — may be fingerprinting installed apps for tracking or targeting.",
            evidence=f"Sample schemes: {', '.join(str(s) for s in queried[:10])}",
        ))

    return findings


# ---------------------------------------------------------------------------
# Entitlements analysis
# ---------------------------------------------------------------------------

def _extract_entitlements(zf: zipfile.ZipFile, names: list[str], app_dir: str) -> Optional[dict]:
    """
    Extract entitlements from the .xcent file or embedded.mobileprovision.
    The .xcent file is sometimes present in dev builds. For production builds,
    entitlements are embedded in the Mach-O binary's __ENTITLEMENTS section —
    we scan raw binary data for the plist XML.
    """
    # Try .xcent file first
    for name in names:
        if name.startswith(app_dir) and name.endswith(".xcent"):
            try:
                data = zf.read(name)
                return plistlib.loads(data)
            except Exception:
                pass

    # Try to extract from embedded.mobileprovision (contains a CMS blob with embedded plist)
    provision_path = _find_file(names, app_dir, "embedded.mobileprovision")
    if provision_path:
        try:
            data = zf.read(provision_path)
            entitlements = _parse_entitlements_from_mobileprovision(data)
            if entitlements:
                return entitlements
        except Exception:
            pass

    return None


def _parse_entitlements_from_mobileprovision(data: bytes) -> Optional[dict]:
    """
    Extract entitlements plist from a .mobileprovision file.
    The file is a CMS (PKCS#7) envelope; the entitlements are stored as XML plist.
    """
    # Entitlements appear as a plist XML blob inside the binary
    start_marker = b"<key>Entitlements</key>"
    plist_start = b"<dict>"
    plist_end = b"</dict>"

    idx = data.find(start_marker)
    if idx == -1:
        return None

    # Find the <dict> after the Entitlements key
    dict_start = data.find(plist_start, idx)
    if dict_start == -1:
        return None

    dict_end = data.find(plist_end, dict_start)
    if dict_end == -1:
        return None

    xml_chunk = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n" + data[dict_start:dict_end + len(plist_end)] + b"\n</plist>"

    try:
        return plistlib.loads(xml_chunk)
    except Exception:
        return None


def _analyze_entitlements(entitlements: dict) -> list[Finding]:
    findings = []

    # Debug entitlement — allows attaching debugger to the process
    if entitlements.get("com.apple.security.get-task-allow") is True:
        findings.append(Finding(
            category="privilege_escalation",
            severity="high",
            rule="entitlement_debug_allowed",
            description="com.apple.security.get-task-allow is true — app allows debugger attachment. Should only exist in development builds.",
            evidence="com.apple.security.get-task-allow = true",
        ))

    # Private Apple entitlements (not allowed for App Store apps, suggests enterprise/jailbreak)
    private_ents = [k for k in entitlements if k.startswith("com.apple.private.")]
    if private_ents:
        findings.append(Finding(
            category="privilege_escalation",
            severity="critical",
            rule="private_entitlements",
            description="App uses private Apple entitlements — indicates a jailbroken distribution or enterprise certificate abuse.",
            evidence=f"Private entitlements: {', '.join(private_ents[:5])}",
        ))

    # Keychain sharing with wildcard / too many groups
    keychain_groups = entitlements.get("keychain-access-groups", [])
    if isinstance(keychain_groups, list):
        wildcards = [g for g in keychain_groups if "*" in str(g)]
        if wildcards:
            findings.append(Finding(
                category="data_collection",
                severity="high",
                rule="keychain_wildcard_access",
                description="App uses wildcard keychain access group — can access keychain items from any app sharing the same team ID.",
                evidence=f"Groups: {', '.join(str(g) for g in wildcards[:3])}",
            ))

    # App Groups with cross-app data sharing
    app_groups = entitlements.get("com.apple.security.application-groups", [])
    if isinstance(app_groups, list) and len(app_groups) > 5:
        findings.append(Finding(
            category="data_collection",
            severity="low",
            rule="excessive_app_groups",
            description=f"App belongs to {len(app_groups)} application groups — broad cross-app data sharing.",
            evidence=f"Groups: {', '.join(str(g) for g in app_groups[:5])}",
        ))

    return findings


# ---------------------------------------------------------------------------
# Binary string extraction and analysis
# ---------------------------------------------------------------------------

_MIN_STRING_LEN = 6
_PRINTABLE = re.compile(rb"[\x20-\x7E]{6,}")


def _extract_strings(binary_data: bytes, max_strings: int = 30000) -> list[str]:
    """Extract printable ASCII strings from binary data (like the `strings` command)."""
    results = []
    for m in _PRINTABLE.finditer(binary_data):
        results.append(m.group(0).decode("ascii", errors="replace"))
        if len(results) >= max_strings:
            break
    return results


# Insecure random API usage
_INSECURE_RANDOM_PATTERN = re.compile(r"\b(rand|srand|random|srandom|drand48)\b")

# Hardcoded secret patterns
_HARDCODED_SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]"), "hardcoded_password"),
    (re.compile(r"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"][^'\"]{8,}['\"]"), "hardcoded_api_key"),
    (re.compile(r"(?i)private[_-]?key\s*[=:]\s*['\"][^'\"]{8,}['\"]"), "hardcoded_private_key"),
    (re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "embedded_private_key"),
    (re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['\"][^'\"]{8,}['\"]"), "aws_secret_key"),
]

# Deprecated/insecure crypto
_INSECURE_CRYPTO_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (
        re.compile(r"\bkCCAlgorithmDES\b|\bkCCAlgorithm3DES\b"),
        "insecure_crypto_des",
        "Use of DES or 3DES via CommonCrypto — deprecated, insecure symmetric encryption.",
    ),
    (
        re.compile(r"\bkCCAlgorithmRC4\b|\bRC4\b"),
        "insecure_crypto_rc4",
        "RC4 usage detected — broken stream cipher, vulnerable to multiple attacks.",
    ),
    (
        re.compile(r"\bCC_MD5\b|\bMD5\b.*\bhash\b|\bMD5\b.*\bdigest\b", re.IGNORECASE),
        "insecure_hash_md5",
        "MD5 hashing detected — cryptographically broken, not suitable for security.",
    ),
    (
        re.compile(r"\bCC_SHA1\b|\bSHA1\b.*\bhash\b|\bSHA1\b.*\bdigest\b", re.IGNORECASE),
        "insecure_hash_sha1",
        "SHA-1 hashing detected — deprecated, collision attacks exist.",
    ),
]

# Insecure keychain accessibility
_INSECURE_KEYCHAIN_PATTERNS = [
    ("kSecAttrAccessibleAlways", "keychain_accessible_always",
     "kSecAttrAccessibleAlways used — keychain item accessible even when device is locked; never appropriate."),
    ("kSecAttrAccessibleAlwaysThisDeviceOnly", "keychain_accessible_always_device",
     "kSecAttrAccessibleAlwaysThisDeviceOnly used — keychain item accessible when locked; use WhenUnlocked instead."),
]

# C2 / suspicious URL patterns
_C2_URL_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}[:/]"),
        "c2_ip_url",
        "backdoor",
        "URL pointing to a raw IP address — common C2 pattern.",
    ),
    (
        re.compile(r"https?://[a-z2-7]{16,56}\.onion", re.IGNORECASE),
        "tor_onion_url",
        "backdoor",
        "TOR .onion URL — strong C2 indicator.",
    ),
    (
        re.compile(r"https?://[^/\s]+\.(ddns\.net|no-ip\.(com|org)|dyndns\.(org|com)|hopto\.org)", re.IGNORECASE),
        "dynamic_dns_url",
        "backdoor",
        "Dynamic DNS domain — frequently used for malware C2.",
    ),
    (
        re.compile(r"https?://(pastebin\.com|paste\.ee|hastebin\.com)/raw/", re.IGNORECASE),
        "pastebin_c2",
        "backdoor",
        "Pastebin raw URL — used to fetch C2 commands.",
    ),
]


def _analyze_binary_strings(strings: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    combined = "\n".join(strings)

    # Insecure random
    if "insecure_random" not in seen:
        match = _INSECURE_RANDOM_PATTERN.search(combined)
        if match:
            findings.append(Finding(
                category="data_collection",
                severity="low",
                rule="insecure_random",
                description="Insecure random number generator detected (rand/srand/random) — not suitable for cryptographic use.",
                evidence=match.group(0),
            ))
            seen.add("insecure_random")

    # Hardcoded secrets
    for pattern, rule in _HARDCODED_SECRET_PATTERNS:
        if rule in seen:
            continue
        match = pattern.search(combined)
        if match:
            evidence = match.group(0)[:120]
            # Redact any actual secret value for safety
            evidence = re.sub(r"(['\"])[^'\"]{4}[^'\"]*(['\"])", r"\1***\2", evidence)
            findings.append(Finding(
                category="data_collection",
                severity="high",
                rule=rule,
                description=f"Hardcoded credential pattern detected ({rule.replace('_', ' ')}) — secrets should not be embedded in binaries.",
                evidence=evidence,
            ))
            seen.add(rule)

    # Insecure crypto
    for pattern, rule, description in _INSECURE_CRYPTO_PATTERNS:
        if rule in seen:
            continue
        if pattern.search(combined):
            findings.append(Finding(
                category="data_collection",
                severity="medium",
                rule=rule,
                description=description,
                evidence=rule.replace("_", " "),
            ))
            seen.add(rule)

    # Insecure keychain accessibility
    for symbol, rule, description in _INSECURE_KEYCHAIN_PATTERNS:
        if rule in seen:
            continue
        if symbol in combined:
            findings.append(Finding(
                category="data_collection",
                severity="high",
                rule=rule,
                description=description,
                evidence=symbol,
            ))
            seen.add(rule)

    # C2 URL patterns
    for pattern, rule, category, description in _C2_URL_PATTERNS:
        if rule in seen:
            continue
        matches = pattern.findall(combined)
        if matches:
            findings.append(Finding(
                category=category,
                severity="high",
                rule=rule,
                description=description,
                evidence=str(matches[0])[:200] if matches else "",
            ))
            seen.add(rule)

    return findings


# ---------------------------------------------------------------------------
# Tracker / SDK detection
# ---------------------------------------------------------------------------

# Known tracker/ad SDK framework bundle names (directory names inside Frameworks/)
_TRACKER_FRAMEWORKS: dict[str, tuple[str, str]] = {
    "FacebookCore.framework": ("data_collection", "Facebook Core SDK — user tracking and analytics."),
    "FBSDKCoreKit.framework": ("data_collection", "Facebook SDK Core — user tracking and advertising."),
    "GoogleAnalytics.framework": ("data_collection", "Google Analytics SDK — user behavior tracking."),
    "FirebaseAnalytics.framework": ("data_collection", "Firebase Analytics — comprehensive user event tracking."),
    "Crashlytics.framework": ("data_collection", "Crashlytics — crash reporting, may collect device identifiers."),
    "Amplitude.framework": ("data_collection", "Amplitude Analytics — user analytics and event tracking."),
    "AmplitudeSwift.framework": ("data_collection", "Amplitude Swift SDK — user analytics."),
    "Mixpanel.framework": ("data_collection", "Mixpanel Analytics — user event tracking."),
    "Appsflyer.framework": ("data_collection", "AppsFlyer — mobile attribution and analytics tracking."),
    "AppsFlyerLib.framework": ("data_collection", "AppsFlyer SDK — mobile attribution tracking."),
    "Branch.framework": ("data_collection", "Branch.io — deep linking and user attribution."),
    "Braze.framework": ("data_collection", "Braze (formerly Appboy) — user engagement and tracking."),
    "Appboy.framework": ("data_collection", "Braze (Appboy) SDK — CRM and user tracking."),
    "Adjust.framework": ("data_collection", "Adjust SDK — mobile attribution and analytics."),
    "Singular.framework": ("data_collection", "Singular SDK — mobile attribution tracking."),
    "MoEngage.framework": ("data_collection", "MoEngage — user engagement and analytics."),
    "CleverTap.framework": ("data_collection", "CleverTap — user analytics and engagement tracking."),
    "OneSignal.framework": ("data_collection", "OneSignal — push notification and user tracking."),
    "Chartboost.framework": ("data_collection", "Chartboost — in-app advertising and tracking."),
    "AdColony.framework": ("data_collection", "AdColony — video ad network and tracking."),
    "MoPub.framework": ("data_collection", "MoPub (Twitter) — ad mediation and tracking."),
    "InMobi.framework": ("data_collection", "InMobi — mobile advertising and tracking."),
    "Smaato.framework": ("data_collection", "Smaato — mobile advertising and tracking."),
    "IronSource.framework": ("data_collection", "ironSource — ad mediation and user tracking."),
    "UnityAds.framework": ("data_collection", "Unity Ads — advertising and analytics."),
    "Vungle.framework": ("data_collection", "Vungle — in-app advertising and tracking."),
    "AppLovin.framework": ("data_collection", "AppLovin — ad network and analytics."),
    "Kochava.framework": ("data_collection", "Kochava — mobile attribution and analytics."),
    "Tenjin.framework": ("data_collection", "Tenjin — mobile attribution and revenue analytics."),
    "Flurry.framework": ("data_collection", "Flurry Analytics — user behavior tracking."),
    "Countly.framework": ("data_collection", "Countly — analytics and crash reporting."),
    "Instabug.framework": ("data_collection", "Instabug — bug reporting and user feedback (collects device info)."),
    "Segment.framework": ("data_collection", "Segment — data pipeline and analytics tracking."),
}


def _detect_trackers(names: list[str], app_dir: str) -> list[Finding]:
    """Scan the Frameworks/ directory for known tracker/ad SDK bundles."""
    findings: list[Finding] = []
    frameworks_dir = f"{app_dir}Frameworks/"
    detected: list[str] = []
    categories_seen: set[str] = set()

    for name in names:
        if not name.startswith(frameworks_dir):
            continue
        # Get the immediate subdirectory name (framework bundle)
        relative = name[len(frameworks_dir):]
        parts = relative.split("/")
        if not parts:
            continue
        framework_name = parts[0]
        if framework_name in _TRACKER_FRAMEWORKS and framework_name not in categories_seen:
            category, desc = _TRACKER_FRAMEWORKS[framework_name]
            detected.append(f"{framework_name}: {desc}")
            categories_seen.add(framework_name)

    if detected:
        findings.append(Finding(
            category="data_collection",
            severity="low",
            rule="tracker_sdk_detected",
            description=f"Known tracker/ad SDK frameworks detected ({len(detected)} total). Review for user privacy compliance (GDPR/CCPA).",
            evidence="\n".join(detected[:10]),
        ))

    return findings


# ---------------------------------------------------------------------------
# Provisioning profile analysis
# ---------------------------------------------------------------------------

def _analyze_provisioning_profile(zf: zipfile.ZipFile, provision_path: str) -> list[Finding]:
    """Check provisioning profile type and expiry."""
    findings = []
    try:
        data = zf.read(provision_path)
        raw = data.decode("utf-8", errors="replace")

        # Detect development vs. distribution profile
        # Development profiles contain "get-task-allow = true" in entitlements
        if "get-task-allow" in raw and "<true/>" in raw[raw.find("get-task-allow"):raw.find("get-task-allow") + 50]:
            findings.append(Finding(
                category="privilege_escalation",
                severity="medium",
                rule="development_provisioning_profile",
                description="IPA contains a development provisioning profile — should not be distributed publicly. Debug capabilities may be enabled.",
                evidence="embedded.mobileprovision contains get-task-allow=true",
            ))

        # Detect ProvisionsAllDevices (enterprise wildcard distribution)
        if "ProvisionsAllDevices" in raw:
            findings.append(Finding(
                category="privilege_escalation",
                severity="medium",
                rule="enterprise_provisioning_wildcard",
                description="IPA uses an enterprise provisioning profile that provisions all devices — bypasses App Store review.",
                evidence="ProvisionsAllDevices key found in embedded.mobileprovision",
            ))

    except Exception:
        pass

    return findings


# ---------------------------------------------------------------------------
# Risk scoring and verdict (mirrors APK analyzer logic)
# ---------------------------------------------------------------------------

def _compute_risk_score(findings: list[Finding]) -> int:
    severity_weights = {"critical": 30, "high": 15, "medium": 8, "low": 3}
    score = sum(severity_weights.get(f.severity, 0) for f in findings)
    return min(score, 100)


def _determine_verdict(risk_score: int, categories: list[str]) -> str:
    hard_pha = {
        "backdoor", "ransomware", "rooting", "trojan", "spyware",
        "commercial_spyware", "hostile_downloader", "privilege_escalation",
    }
    if any(c in hard_pha for c in categories):
        return "pha"
    if risk_score >= 60:
        return "pha"
    if risk_score >= 25:
        return "suspicious"
    return "clean"


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()
