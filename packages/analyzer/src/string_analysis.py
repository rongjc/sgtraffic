"""
String/URL extraction — detects C2 patterns, suspicious URL schemes,
and base64-encoded payloads in DEX string constants.
"""
import base64
import re
from .models import Finding


# Suspicious URL schemes / C2 indicators
_SUSPICIOUS_URL_PATTERNS = [
    # Raw IP addresses as C2 (not in private ranges)
    (
        re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}[:/]"),
        "backdoor",
        "high",
        "c2_ip_url",
        "URL pointing to a raw IP address — common C2 communication pattern.",
    ),
    # .onion TOR hidden services
    (
        re.compile(r"https?://[a-z2-7]{16,56}\.onion", re.IGNORECASE),
        "backdoor",
        "critical",
        "tor_onion_url",
        "TOR .onion URL found — strong indicator of C2 communication over TOR.",
    ),
    # Dynamic DNS (common malware infrastructure)
    (
        re.compile(r"https?://[^/\s]+\.(ddns\.net|no-ip\.(com|org|biz)|dyndns\.(org|com)|hopto\.org|servebeer\.com|myftp\.(org|biz)|redirectme\.net)", re.IGNORECASE),
        "backdoor",
        "high",
        "dynamic_dns_url",
        "Dynamic DNS domain found — frequently used for malware C2 infrastructure.",
    ),
    # Pastebin-like sites used for C2
    (
        re.compile(r"https?://(pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.co|0bin\.net)/raw/", re.IGNORECASE),
        "backdoor",
        "high",
        "pastebin_c2",
        "Pastebin raw URL found — used by malware to fetch C2 commands or payloads.",
    ),
    # ngrok tunnels (common in testing malware)
    (
        re.compile(r"https?://[a-z0-9]+\.ngrok\.(io|app)", re.IGNORECASE),
        "backdoor",
        "medium",
        "ngrok_tunnel",
        "ngrok tunnel URL — sometimes used to proxy C2 traffic.",
    ),
]

# Suspicious non-HTTP schemes
_SUSPICIOUS_SCHEMES = [
    (
        re.compile(r"socket://", re.IGNORECASE),
        "backdoor",
        "medium",
        "raw_socket_url",
        "Raw socket URL — direct C2 socket connection pattern.",
    ),
    (
        re.compile(r"ftp://", re.IGNORECASE),
        "data_collection",
        "low",
        "ftp_url",
        "FTP URL — potential data exfiltration channel.",
    ),
]

# Keywords in string literals that suggest malicious intent
_KEYWORD_RULES: list[tuple[re.Pattern, str, str, str, str]] = [
    (
        re.compile(r"\b(su\s|/su\b|/system/bin/su|/system/xbin/su)", re.IGNORECASE),
        "rooting",
        "critical",
        "su_binary_reference",
        "References to 'su' binary — rooting or root exploit behavior.",
    ),
    (
        re.compile(r"/system/bin/(busybox|supersu|magisk)", re.IGNORECASE),
        "rooting",
        "high",
        "root_tool_reference",
        "References to rooting tools (busybox, SuperSU, Magisk).",
    ),
    (
        re.compile(r"\bransomware\b|\bencrypt your files\b|\byour files have been encrypted\b", re.IGNORECASE),
        "ransomware",
        "critical",
        "ransomware_string",
        "Ransomware-related strings found in the binary.",
    ),
    (
        re.compile(r"\bcredit.?card\b.{0,50}\b(number|cvv|expiry)\b", re.IGNORECASE),
        "phishing",
        "high",
        "credit_card_harvest_string",
        "Strings suggesting credit card harvesting behavior.",
    ),
    (
        re.compile(r"com\.android\.vending\.BILLING", re.IGNORECASE),
        "billing_fraud",
        "medium",
        "billing_api_string",
        "Google Play billing API string — verify legitimate use vs. billing fraud.",
    ),
]

# Minimum length for base64 strings to check (avoid false positives on short strings)
_B64_MIN_LENGTH = 40
_B64_PATTERN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def analyze_strings(dx) -> list[Finding]:
    """
    Accepts an androguard Analysis object.
    Scans string constants in the DEX for C2 patterns, suspicious URLs, and base64 payloads.
    """
    findings: list[Finding] = []
    seen_rules: set[str] = set()

    try:
        all_strings = _collect_strings(dx)
        findings.extend(_check_url_patterns(all_strings, seen_rules))
        findings.extend(_check_keywords(all_strings, seen_rules))
        findings.extend(_check_base64_payloads(all_strings, seen_rules))
    except Exception:
        pass

    return findings


def _collect_strings(dx) -> list[str]:
    """Extract all string constants from the DEX."""
    strings = []
    try:
        for _, s in dx.get_strings_analysis().items():
            strings.append(str(s.get_orig_value()))
            if len(strings) > 50000:  # Safety cap
                break
    except Exception:
        pass
    return strings


def _check_url_patterns(strings: list[str], seen_rules: set[str]) -> list[Finding]:
    findings = []
    combined = "\n".join(strings)

    for pattern, category, severity, rule, description in _SUSPICIOUS_URL_PATTERNS:
        if rule in seen_rules:
            continue
        matches = pattern.findall(combined)
        if matches:
            # Find actual full URL matches for evidence
            url_matches = pattern.findall(combined)
            evidence = ", ".join(str(m) for m in url_matches[:3])
            findings.append(Finding(
                category=category,
                severity=severity,
                rule=rule,
                description=description,
                evidence=evidence,
            ))
            seen_rules.add(rule)

    for pattern, category, severity, rule, description in _SUSPICIOUS_SCHEMES:
        if rule in seen_rules:
            continue
        if pattern.search(combined):
            findings.append(Finding(
                category=category,
                severity=severity,
                rule=rule,
                description=description,
                evidence="See string constants in DEX",
            ))
            seen_rules.add(rule)

    return findings


def _check_keywords(strings: list[str], seen_rules: set[str]) -> list[Finding]:
    findings = []
    combined = "\n".join(strings)

    for pattern, category, severity, rule, description in _KEYWORD_RULES:
        if rule in seen_rules:
            continue
        match = pattern.search(combined)
        if match:
            findings.append(Finding(
                category=category,
                severity=severity,
                rule=rule,
                description=description,
                evidence=match.group(0)[:200],
            ))
            seen_rules.add(rule)

    return findings


def _check_base64_payloads(strings: list[str], seen_rules: set[str]) -> list[Finding]:
    """Detect strings that decode to suspicious base64 payloads."""
    if "base64_payload" in seen_rules:
        return []

    findings = []
    for s in strings:
        if len(s) < _B64_MIN_LENGTH:
            continue
        match = _B64_PATTERN.search(s)
        if not match:
            continue
        candidate = match.group(0)
        try:
            decoded = base64.b64decode(candidate + "==").decode("utf-8", errors="replace")
            # Check if decoded content looks like a URL or command
            if re.search(r"https?://|http://|\bexec\b|\bsu\b|/bin/sh|cmd\.exe", decoded, re.IGNORECASE):
                findings.append(Finding(
                    category="backdoor",
                    severity="high",
                    rule="base64_payload",
                    description="Base64-encoded string decodes to a suspicious URL or command — common obfuscation technique.",
                    evidence=f"Encoded: {candidate[:80]}... | Decoded: {decoded[:120]}",
                ))
                seen_rules.add("base64_payload")
                break
        except Exception:
            continue

    return findings
