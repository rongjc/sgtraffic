"""
iOS source code analyzer.
Analyzes unzipped iOS (Xcode) projects without compilation.
Detects insecure patterns in Swift/ObjC sources, Info.plist, and CocoaPods/SPM dependency files.
"""
import plistlib
import re
from pathlib import Path

from .models import Finding


# ---------------------------------------------------------------------------
# Insecure source-code patterns for Swift / Objective-C
# ---------------------------------------------------------------------------

SWIFT_OBJC_RULES: list[tuple[str, str, str, str, str]] = [
    # (rule_id, category, severity, description, regex_pattern)
    (
        "insecure_random_arc4random",
        "data_collection",
        "medium",
        "arc4random / arc4random_uniform used for security — use SecRandomCopyBytes instead.",
        r'\barc4random(?:_uniform)?\s*\(',
    ),
    (
        "insecure_random_rand",
        "data_collection",
        "medium",
        "rand() / random() used for security-sensitive operation — use SecRandomCopyBytes.",
        r'\brand\s*\(\s*\)|\brandom\s*\(\s*\)',
    ),
    (
        "hardcoded_secret",
        "data_collection",
        "high",
        "Potential hardcoded secret or API key in source.",
        r'(?i)(password|passwd|secret|api_?key|apikey|access_?token|auth_?token|private_?key)\s*[=:]\s*["\'][^"\']{8,}["\']',
    ),
    (
        "hardcoded_aws_key",
        "data_collection",
        "critical",
        "Hardcoded AWS access key found.",
        r'AKIA[0-9A-Z]{16}',
    ),
    (
        "cleartext_http",
        "data_collection",
        "medium",
        "Cleartext HTTP URL found — data transmitted unencrypted.",
        r'["\']http://(?!localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.)[^"\']{4,}["\']',
    ),
    (
        "uipasteboard_sensitive",
        "data_collection",
        "medium",
        "UIPasteboard usage detected — sensitive data may be copied to the pasteboard.",
        r'\bUIPasteboard\b',
    ),
    (
        "nsuserdefaults_sensitive",
        "data_collection",
        "low",
        "NSUserDefaults stores data in plaintext — avoid storing sensitive values here.",
        r'UserDefaults\.standard\.set\s*\(',
    ),
    (
        "deprecated_md5_cc",
        "data_collection",
        "medium",
        "CommonCrypto MD5 (kCCAlgorithmMD5 or CC_MD5) used — collision-vulnerable.",
        r'CC_MD5\s*\(|kCCAlgorithmMD5',
    ),
    (
        "deprecated_sha1_cc",
        "data_collection",
        "low",
        "CommonCrypto SHA-1 used — deprecated for cryptographic purposes.",
        r'CC_SHA1\s*\(|kCCAlgorithmSHA1',
    ),
    (
        "ssl_allow_any_cert",
        "data_collection",
        "critical",
        "SSL/TLS certificate validation disabled — MITM attack risk.",
        r'(?i)setAllowsAnyHTTPSCertificate|URLSession.*allowsInvalidCertificates\s*=\s*true',
    ),
    (
        "webview_allow_all_files",
        "trojan",
        "medium",
        "WKWebView or UIWebView allows arbitrary file access.",
        r'allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs',
    ),
    (
        "keychain_accessible_always",
        "data_collection",
        "medium",
        "Keychain item accessible kSecAttrAccessibleAlways — accessible even when device is locked.",
        r'kSecAttrAccessibleAlways(?!ThisDevice)',
    ),
    (
        "nslog_sensitive",
        "data_collection",
        "medium",
        "NSLog may expose sensitive data in production logs.",
        r'(?i)NSLog\s*\(@?["\'][^"\']*(?:password|token|secret|key|credential)[^"\']*["\']',
    ),
    (
        "deprecated_uiwebview",
        "trojan",
        "low",
        "Deprecated UIWebView used — replaced by WKWebView; may expose XSS risks.",
        r'\bUIWebView\b',
    ),
    (
        "sql_injection_fmdb",
        "data_collection",
        "high",
        "FMDB executeQuery with string concatenation — possible SQL injection.",
        r'executeQuery\s*:\s*@?["\'][^"\']*["\'\s]*\+',
    ),
]


# ---------------------------------------------------------------------------
# Known vulnerable CocoaPods dependency versions
# ---------------------------------------------------------------------------

VULNERABLE_PODS: list[tuple[str, str, str, str]] = [
    # (rule_id, description, severity, pattern)
    (
        "vuln_alamofire_old",
        "Alamofire < 5.6.1 has known TLS vulnerabilities.",
        "medium",
        r"pod\s+['\"]Alamofire['\"],\s*['\"]~?>?\s*[0-4]\.",
    ),
    (
        "vuln_afnetworking_old",
        "AFNetworking < 3.2.1 has SSL certificate validation bypass (CVE-2020-10289).",
        "high",
        r"pod\s+['\"]AFNetworking['\"],\s*['\"]~?>?\s*[012]\.",
    ),
    (
        "vuln_sdwebimage_old",
        "SDWebImage < 5.0 has known vulnerabilities.",
        "low",
        r"pod\s+['\"]SDWebImage['\"],\s*['\"]~?>?\s*[0-4]\.",
    ),
    (
        "vuln_realm_old",
        "Realm < 10.x had encryption key exposure issues.",
        "medium",
        r"pod\s+['\"]Realm['\"],\s*['\"]~?>?\s*[0-9]\.",
    ),
]


# ---------------------------------------------------------------------------
# Info.plist checks
# ---------------------------------------------------------------------------

def _analyze_info_plist(plist_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with open(plist_path, "rb") as f:
            plist = plistlib.load(f)
    except Exception:
        # Try reading as XML text
        try:
            content = plist_path.read_text(encoding="utf-8", errors="replace")
            plist = plistlib.loads(content.encode())
        except Exception:
            return findings

    # ATS — App Transport Security
    ats = plist.get("NSAppTransportSecurity", {})
    if ats.get("NSAllowsArbitraryLoads", False):
        findings.append(Finding(
            category="data_collection",
            severity="high",
            rule="ats_allows_arbitrary_loads",
            description="NSAllowsArbitraryLoads=YES disables ATS — all cleartext HTTP connections are permitted.",
            evidence="Info.plist: NSAppTransportSecurity.NSAllowsArbitraryLoads",
        ))

    if ats.get("NSAllowsArbitraryLoadsForMedia", False):
        findings.append(Finding(
            category="data_collection",
            severity="medium",
            rule="ats_allows_arbitrary_media",
            description="NSAllowsArbitraryLoadsForMedia=YES allows cleartext media streaming.",
            evidence="Info.plist: NSAllowsArbitraryLoadsForMedia",
        ))

    if ats.get("NSAllowsArbitraryLoadsInWebContent", False):
        findings.append(Finding(
            category="trojan",
            severity="medium",
            rule="ats_allows_arbitrary_web",
            description="NSAllowsArbitraryLoadsInWebContent=YES — web content loaded over HTTP.",
            evidence="Info.plist: NSAllowsArbitraryLoadsInWebContent",
        ))

    exception_domains = ats.get("NSExceptionDomains", {})
    for domain, domain_config in exception_domains.items():
        if domain_config.get("NSExceptionAllowsInsecureHTTPLoads", False):
            findings.append(Finding(
                category="data_collection",
                severity="medium",
                rule="ats_exception_http_domain",
                description=f"ATS exception allows HTTP for domain: {domain}",
                evidence=f"Info.plist: NSExceptionDomains.{domain}",
            ))

    # Privacy descriptions
    PRIVACY_KEYS = {
        "NSCameraUsageDescription": "camera",
        "NSMicrophoneUsageDescription": "microphone",
        "NSLocationWhenInUseUsageDescription": "location",
        "NSContactsUsageDescription": "contacts",
        "NSPhotoLibraryUsageDescription": "photo library",
    }
    for key, resource in PRIVACY_KEYS.items():
        if key in plist and not plist[key].strip():
            findings.append(Finding(
                category="data_collection",
                severity="low",
                rule=f"missing_privacy_description_{resource.replace(' ', '_')}",
                description=f"Empty privacy usage description for {resource} — required by App Store.",
                evidence=f"Info.plist: {key} is empty",
            ))

    return findings


# ---------------------------------------------------------------------------
# Podfile / Package.swift scanning
# ---------------------------------------------------------------------------

def _analyze_podfile(podfile_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        content = podfile_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings

    for rule_id, description, severity, pattern in VULNERABLE_PODS:
        if re.search(pattern, content, re.IGNORECASE):
            findings.append(Finding(
                category="data_collection",
                severity=severity,
                rule=rule_id,
                description=description,
                evidence=str(podfile_path),
            ))
    return findings


# ---------------------------------------------------------------------------
# Swift / Objective-C source scanning
# ---------------------------------------------------------------------------

def _scan_source_file(file_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings

    for rule_id, category, severity, description, pattern in SWIFT_OBJC_RULES:
        match = re.search(pattern, content)
        if match:
            findings.append(Finding(
                category=category,
                severity=severity,
                rule=rule_id,
                description=description,
                evidence=f"{file_path.name}: ...{match.group(0)[:80]}...",
            ))
    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_ios_source(project_dir: Path) -> list[Finding]:
    """
    Analyze an extracted iOS source project directory.
    Returns a list of Finding objects.
    """
    findings: list[Finding] = []
    seen_rules: set[str] = set()

    def add_findings(new_findings: list[Finding]) -> None:
        for f in new_findings:
            if f.rule not in seen_rules:
                findings.append(f)
                seen_rules.add(f.rule)

    # 1. Info.plist
    for plist_path in project_dir.rglob("Info.plist"):
        add_findings(_analyze_info_plist(plist_path))

    # 2. Podfile
    for podfile in project_dir.rglob("Podfile"):
        add_findings(_analyze_podfile(podfile))

    # 3. Swift / Objective-C source files
    source_extensions = {".swift", ".m", ".mm", ".h"}
    for src_file in project_dir.rglob("*"):
        if src_file.suffix in source_extensions and src_file.is_file():
            add_findings(_scan_source_file(src_file))

    return findings
