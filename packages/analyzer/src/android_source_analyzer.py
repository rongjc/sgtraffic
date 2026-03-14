"""
Android source code analyzer.
Analyzes unzipped Android (Gradle) projects without compilation.
Detects insecure patterns in Java/Kotlin sources, AndroidManifest.xml, and build.gradle.
"""
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .models import Finding


# ---------------------------------------------------------------------------
# Insecure source-code patterns for Java / Kotlin
# ---------------------------------------------------------------------------

JAVA_KOTLIN_RULES: list[tuple[str, str, str, str, str]] = [
    # (rule_id, category, severity, description, regex_pattern)
    (
        "hardcoded_secret",
        "data_collection",
        "high",
        "Potential hardcoded secret or API key detected in source code.",
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
        "sql_injection",
        "data_collection",
        "high",
        "Possible SQL injection: raw string concatenation in query.",
        r'(?i)(rawQuery|execSQL|query)\s*\(\s*["\'][^"\']*["\'\s]*\+',
    ),
    (
        "insecure_webview_js",
        "trojan",
        "high",
        "WebView has JavaScript enabled — potential XSS/code-injection vector.",
        r'setJavaScriptEnabled\s*\(\s*true\s*\)',
    ),
    (
        "webview_allow_file_access",
        "trojan",
        "medium",
        "WebView allows file system access.",
        r'setAllowFileAccess\s*\(\s*true\s*\)',
    ),
    (
        "webview_add_javascript_interface",
        "trojan",
        "high",
        "addJavascriptInterface exposes Java objects to JavaScript — remote code execution risk.",
        r'addJavascriptInterface\s*\(',
    ),
    (
        "cleartext_http",
        "data_collection",
        "medium",
        "Cleartext HTTP URL found in source code — data transmitted unencrypted.",
        r'["\']http://(?!localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.)[^"\']{4,}["\']',
    ),
    (
        "weak_crypto_des",
        "data_collection",
        "high",
        "DES/3DES encryption used — weak, broken cipher.",
        r'Cipher\.getInstance\s*\(\s*["\']DES["\']',
    ),
    (
        "weak_crypto_md5",
        "data_collection",
        "medium",
        "MD5 used as a cryptographic hash — collision-vulnerable.",
        r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']',
    ),
    (
        "weak_crypto_sha1",
        "data_collection",
        "low",
        "SHA-1 used — deprecated for cryptographic purposes.",
        r'MessageDigest\.getInstance\s*\(\s*["\']SHA-1["\']',
    ),
    (
        "insecure_random",
        "data_collection",
        "medium",
        "java.util.Random used for security-sensitive operation — use SecureRandom instead.",
        r'\bnew\s+Random\s*\(\s*\)',
    ),
    (
        "world_readable_file",
        "data_collection",
        "high",
        "File opened with MODE_WORLD_READABLE — other apps can read the file.",
        r'MODE_WORLD_READABLE',
    ),
    (
        "world_writable_file",
        "data_collection",
        "high",
        "File opened with MODE_WORLD_WRITABLE — other apps can write to the file.",
        r'MODE_WORLD_WRITABLE',
    ),
    (
        "log_sensitive_data",
        "data_collection",
        "medium",
        "Logging call may expose sensitive data (password/token/key in log arguments).",
        r'(?i)Log\.[dviwe]\s*\([^)]*(?:password|token|secret|key|credential)[^)]*\)',
    ),
    (
        "hardcoded_iv",
        "data_collection",
        "high",
        "Hardcoded IV (initialization vector) detected — weakens encryption.",
        r'IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*\]\s*\{',
    ),
    (
        "trust_all_certs",
        "data_collection",
        "critical",
        "Custom TrustManager that trusts all certificates — disables TLS validation.",
        r'checkServerTrusted\s*\([^)]*\)\s*\{?\s*\}',
    ),
    (
        "hostname_verifier_allow_all",
        "data_collection",
        "critical",
        "HostnameVerifier always returns true — SSL hostname verification disabled.",
        r'ALLOW_ALL_HOSTNAME_VERIFIER|verify\s*\([^)]*\)\s*\{\s*return\s+true',
    ),
]

# ---------------------------------------------------------------------------
# Known vulnerable Gradle dependency patterns
# ---------------------------------------------------------------------------

VULNERABLE_GRADLE_DEPS: list[tuple[str, str, str, str]] = [
    # (rule_id, description, severity, pattern)
    (
        "vuln_okhttp_old",
        "OkHttp < 3.12.13 has known vulnerabilities.",
        "medium",
        r'okhttp["\']?\s*,\s*version\s*[=:]\s*["\']?[012]\.',
    ),
    (
        "vuln_log4j",
        "log4j dependency detected — check for Log4Shell (CVE-2021-44228).",
        "critical",
        r'log4j[:\-](?:core|api)[:\-](?:[01]\.|2\.[0-9]\.|2\.1[0-6]\.)',
    ),
    (
        "vuln_gson_old",
        "Gson < 2.8.9 has a deserialization vulnerability.",
        "medium",
        r'com\.google\.code\.gson.*["\']2\.[0-7]\.',
    ),
    (
        "vuln_webview_gms_old",
        "Google Play Services < 11 may expose WebView vulnerabilities.",
        "low",
        r'com\.google\.android\.gms:play-services.*["\'][0-9]\.',
    ),
]


# ---------------------------------------------------------------------------
# Manifest XML checks (raw XML parsing — no androguard needed)
# ---------------------------------------------------------------------------

ANDROID_NAMESPACES = {
    "android": "http://schemas.android.com/apk/res/android",
}


def _analyze_manifest_xml(manifest_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except Exception:
        return findings

    ns = "http://schemas.android.com/apk/res/android"

    # Check debuggable=true
    app_el = root.find("application")
    if app_el is not None:
        debuggable = app_el.get(f"{{{ns}}}debuggable", "false")
        if debuggable.lower() == "true":
            findings.append(Finding(
                category="data_collection",
                severity="high",
                rule="manifest_debuggable",
                description="android:debuggable=true — app is debuggable in production builds.",
                evidence=str(manifest_path.relative_to(manifest_path.parent.parent)),
            ))

        allow_backup = app_el.get(f"{{{ns}}}allowBackup", "true")
        if allow_backup.lower() == "true":
            findings.append(Finding(
                category="data_collection",
                severity="medium",
                rule="manifest_allow_backup",
                description="android:allowBackup=true — app data can be extracted via adb backup.",
                evidence=str(manifest_path.relative_to(manifest_path.parent.parent)),
            ))

        # network_security_config missing
        if app_el.get(f"{{{ns}}}networkSecurityConfig") is None:
            findings.append(Finding(
                category="data_collection",
                severity="low",
                rule="manifest_no_network_security_config",
                description="No networkSecurityConfig defined — cleartext traffic may be permitted on older Android versions.",
                evidence=str(manifest_path.relative_to(manifest_path.parent.parent)),
            ))

    # Check uses-permission for dangerous ones (reuse existing permission logic for raw manifest)
    DANGEROUS_PERMISSIONS = {
        "android.permission.READ_SMS": ("spyware", "high", "perm_read_sms"),
        "android.permission.RECEIVE_SMS": ("spyware", "high", "perm_receive_sms"),
        "android.permission.SEND_SMS": ("billing_fraud", "high", "perm_send_sms"),
        "android.permission.READ_CALL_LOG": ("spyware", "high", "perm_read_call_log"),
        "android.permission.PROCESS_OUTGOING_CALLS": ("spyware", "medium", "perm_process_calls"),
        "android.permission.RECORD_AUDIO": ("spyware", "medium", "perm_record_audio"),
        "android.permission.CAMERA": ("spyware", "low", "perm_camera"),
        "android.permission.ACCESS_FINE_LOCATION": ("spyware", "medium", "perm_fine_location"),
        "android.permission.READ_CONTACTS": ("data_collection", "medium", "perm_read_contacts"),
    }

    for perm_el in root.iter("uses-permission"):
        name = perm_el.get(f"{{{ns}}}name", "")
        if name in DANGEROUS_PERMISSIONS:
            category, severity, rule = DANGEROUS_PERMISSIONS[name]
            findings.append(Finding(
                category=category,
                severity=severity,
                rule=rule,
                description=f"Dangerous permission declared: {name}",
                evidence=name,
            ))

    return findings


# ---------------------------------------------------------------------------
# Gradle dependency scanning
# ---------------------------------------------------------------------------

def _analyze_gradle(gradle_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        content = gradle_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings

    for rule_id, description, severity, pattern in VULNERABLE_GRADLE_DEPS:
        if re.search(pattern, content):
            findings.append(Finding(
                category="data_collection",
                severity=severity,
                rule=rule_id,
                description=description,
                evidence=str(gradle_path),
            ))
    return findings


# ---------------------------------------------------------------------------
# Java / Kotlin source scanning
# ---------------------------------------------------------------------------

def _scan_source_file(file_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings

    for rule_id, category, severity, description, pattern in JAVA_KOTLIN_RULES:
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

def analyze_android_source(project_dir: Path) -> list[Finding]:
    """
    Analyze an extracted Android source project directory.
    Returns a list of Finding objects.
    """
    findings: list[Finding] = []
    seen_rules: set[str] = set()

    def add_findings(new_findings: list[Finding]) -> None:
        for f in new_findings:
            # Deduplicate same rule across many files — keep first occurrence only
            if f.rule not in seen_rules:
                findings.append(f)
                seen_rules.add(f.rule)

    # 1. AndroidManifest.xml
    for manifest in project_dir.rglob("AndroidManifest.xml"):
        add_findings(_analyze_manifest_xml(manifest))

    # 2. Gradle build files
    for gradle in project_dir.rglob("*.gradle"):
        add_findings(_analyze_gradle(gradle))
    for gradle in project_dir.rglob("*.gradle.kts"):
        add_findings(_analyze_gradle(gradle))

    # 3. Java / Kotlin source files
    source_extensions = {".java", ".kt"}
    for src_file in project_dir.rglob("*"):
        if src_file.suffix in source_extensions and src_file.is_file():
            add_findings(_scan_source_file(src_file))

    return findings
