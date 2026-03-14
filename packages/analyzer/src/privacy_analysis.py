"""
Privacy analysis module — detects tracking SDKs, data collection patterns,
and GDPR/CCPA compliance indicators in Android APKs.

Privacy score: 0–100 (higher = more privacy-invasive).
Findings use category 'privacy' for privacy-specific issues.
"""
import re
from .models import Finding


# ── Tracker SDK fingerprint database ──────────────────────────────────────────
# Each entry: (tracker_name, [package_prefix, ...])
# Matched against DEX class names (package paths).

TRACKER_SDK_DB: list[tuple[str, list[str]]] = [
    ("Google Analytics",      ["com/google/android/gms/analytics", "com/google/firebase/analytics"]),
    ("Firebase Analytics",    ["com/google/firebase/analytics"]),
    ("Facebook SDK",          ["com/facebook/analytics", "com/facebook/core", "com/facebook/appevents"]),
    ("Adjust",                ["com/adjust/sdk"]),
    ("AppsFlyer",             ["com/appsflyer"]),
    ("Mixpanel",              ["com/mixpanel/android"]),
    ("Amplitude",             ["com/amplitude/api", "com/amplitude/android"]),
    ("Braze (Appboy)",        ["com/appboy", "com/braze"]),
    ("Flurry",                ["com/flurry/android"]),
    ("Singular",              ["com/singular/sdk"]),
    ("Kochava",               ["com/kochava/base"]),
    ("Branch",                ["io/branch/referral"]),
    ("MoPub",                 ["com/mopub"]),
    ("AdMob",                 ["com/google/android/gms/ads"]),
    ("IronSource",            ["com/ironsource/mediationsdk"]),
    ("Unity Ads",             ["com/unity3d/ads"]),
    ("InMobi",                ["com/inmobi"]),
    ("Chartboost",            ["com/chartboost/sdk"]),
    ("AppLovin",              ["com/applovin"]),
    ("Criteo",                ["com/criteo"]),
    ("Nielsen",               ["com/nielsen"]),
    ("Comscore",              ["com/comscore"]),
    ("Tapad",                 ["com/tapad"]),
    ("Verizon Ads (Oath)",    ["com/oath/ads", "com/verizon/ads"]),
    ("Smaato",                ["com/smaato"]),
    ("Twitter MoPub",         ["com/twitter/sdk/android"]),
    ("Segment",               ["com/segment/analytics"]),
    ("CleverTap",             ["com/clevertap/android"]),
    ("Leanplum",              ["com/leanplum"]),
    ("OneSignal",             ["com/onesignal"]),
    ("DataDog",               ["com/datadog/android"]),
    ("Instabug",              ["com/instabug/library"]),
    ("Bugsnag",               ["com/bugsnag/android"]),
    ("Crashlytics",           ["com/crashlytics/android", "com/google/firebase/crashlytics"]),
    ("Sentry",                ["io/sentry/android"]),
    ("Tapjoy",                ["com/tapjoy"]),
    ("Vungle",                ["com/vungle/warren", "com/vungle/ads"]),
    ("AdColony",              ["com/adcolony"]),
    ("StartApp",              ["com/startapp"]),
    ("Supersonic (IronSource)", ["com/supersonic/ads"]),
]

# ── Privacy-invasive permissions ───────────────────────────────────────────────
_PRIVACY_PERMISSION_RULES: list[tuple[str, str, str, str, str]] = [
    (
        "android.permission.READ_PHONE_STATE",
        "privacy",
        "high",
        "device_id_harvesting_imei",
        "READ_PHONE_STATE allows device ID (IMEI/MEID) harvesting — strong tracking identifier.",
    ),
    (
        "android.permission.READ_PRIVILEGED_PHONE_STATE",
        "privacy",
        "critical",
        "privileged_phone_state",
        "READ_PRIVILEGED_PHONE_STATE provides privileged access to device identifiers — extreme tracking capability.",
    ),
    (
        "android.permission.ACCESS_FINE_LOCATION",
        "privacy",
        "high",
        "fine_location_tracking",
        "ACCESS_FINE_LOCATION enables precise GPS-level tracking of user location.",
    ),
    (
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "privacy",
        "critical",
        "background_location_tracking",
        "ACCESS_BACKGROUND_LOCATION allows continuous location tracking even when the app is not in use.",
    ),
    (
        "android.permission.READ_CONTACTS",
        "privacy",
        "high",
        "contact_list_access",
        "READ_CONTACTS allows harvesting of user contact list — major privacy concern.",
    ),
    (
        "android.permission.READ_CALL_LOG",
        "privacy",
        "high",
        "call_log_access",
        "READ_CALL_LOG exposes call history — sensitive personal data.",
    ),
    (
        "android.permission.READ_SMS",
        "privacy",
        "high",
        "sms_read_privacy",
        "READ_SMS grants access to private SMS messages.",
    ),
    (
        "android.permission.GET_ACCOUNTS",
        "privacy",
        "medium",
        "account_enumeration",
        "GET_ACCOUNTS can enumerate user accounts (email addresses, social accounts) on the device.",
    ),
    (
        "android.permission.BODY_SENSORS",
        "privacy",
        "medium",
        "body_sensor_access",
        "BODY_SENSORS accesses health sensor data (heart rate, etc.) — sensitive health data.",
    ),
    (
        "android.permission.READ_MEDIA_IMAGES",
        "privacy",
        "medium",
        "media_images_access",
        "READ_MEDIA_IMAGES provides access to photos — may expose personal images.",
    ),
]

# ── Clipboard reading (DEX method patterns) ────────────────────────────────────
_CLIPBOARD_CLASS = "android/content/ClipboardManager"
_CLIPBOARD_METHOD = "getPrimaryClip"

# ── GDPR/CCPA consent + privacy policy string patterns ────────────────────────
_CONSENT_PATTERNS = [
    re.compile(r"\bcom\.google\.android\.ump\b", re.IGNORECASE),        # Google UMP
    re.compile(r"\bconsent\s*manager\b", re.IGNORECASE),
    re.compile(r"\bgdpr\b", re.IGNORECASE),
    re.compile(r"\bccpa\b", re.IGNORECASE),
    re.compile(r"\bcookie\s*consent\b", re.IGNORECASE),
    re.compile(r"\bprivacy\s*consent\b", re.IGNORECASE),
    re.compile(r"\bRequestConsentInfoUpdate\b"),
    re.compile(r"\bConsentInformation\b"),
]

_PRIVACY_POLICY_PATTERNS = [
    re.compile(r"https?://[^\s\"'<>]+privacy[^\s\"'<>]{0,60}", re.IGNORECASE),
    re.compile(r"privacy[\s_\-]policy", re.IGNORECASE),
    re.compile(r"privacy[\s_\-]notice", re.IGNORECASE),
    re.compile(r"https?://[^\s\"'<>]+/legal[^\s\"'<>]{0,40}", re.IGNORECASE),
]

_DATA_RETENTION_PATTERNS = [
    re.compile(r"data[\s_\-]retention", re.IGNORECASE),
    re.compile(r"delete[\s_\-]my[\s_\-]data", re.IGNORECASE),
    re.compile(r"right[\s_\-]to[\s_\-]erasure", re.IGNORECASE),
    re.compile(r"opt[\s_\-]out", re.IGNORECASE),
]


# ── Score weights ──────────────────────────────────────────────────────────────
_TRACKER_SCORE_WEIGHT = 8          # per tracker SDK detected
_PERMISSION_WEIGHTS = {
    "critical": 20,
    "high": 12,
    "medium": 6,
}
_NO_CONSENT_PENALTY = 10
_NO_PRIVACY_POLICY_PENALTY = 5
_CLIPBOARD_PENALTY = 8


def analyze_privacy(
    permissions: list[str],
    dx=None,          # androguard Analysis object (optional)
) -> tuple[list[Finding], int, list[str]]:
    """
    Run full privacy analysis.

    Returns:
        findings        — list of Finding objects (category='privacy')
        privacy_score   — 0–100 integer (higher = more invasive)
        trackers        — list of detected tracker SDK names
    """
    findings: list[Finding] = []
    privacy_score = 0
    trackers: list[str] = []

    # 1. Tracker SDK detection (requires DEX analysis)
    if dx is not None:
        trackers, tracker_findings = _detect_tracker_sdks(dx)
        findings.extend(tracker_findings)
        privacy_score += min(len(trackers) * _TRACKER_SCORE_WEIGHT, 40)

    # 2. Privacy-invasive permissions
    perm_set = set(permissions)
    for perm, category, severity, rule, description in _PRIVACY_PERMISSION_RULES:
        if perm in perm_set:
            findings.append(Finding(
                category=category,
                severity=severity,
                rule=rule,
                description=description,
                evidence=perm,
            ))
            privacy_score += _PERMISSION_WEIGHTS.get(severity, 0)

    # 3. Clipboard reading detection
    if dx is not None:
        clipboard_callers = _detect_clipboard_reading(dx)
        if clipboard_callers:
            findings.append(Finding(
                category="privacy",
                severity="medium",
                rule="clipboard_reading",
                description="App reads clipboard contents via ClipboardManager.getPrimaryClip() — can capture passwords, tokens, and sensitive data.",
                evidence="; ".join(clipboard_callers[:3]),
            ))
            privacy_score += _CLIPBOARD_PENALTY

    # 4. GDPR/CCPA compliance checks (string-based)
    if dx is not None:
        all_strings = _collect_strings(dx)
        consent_found, policy_found, retention_found = _check_compliance_strings(all_strings)

        if not consent_found:
            findings.append(Finding(
                category="privacy",
                severity="medium",
                rule="no_consent_mechanism",
                description="No consent management mechanism detected (no GDPR/CCPA consent strings or Google UMP). Apps collecting personal data must obtain user consent.",
                evidence="No consent strings found in DEX",
            ))
            privacy_score += _NO_CONSENT_PENALTY

        if not policy_found:
            findings.append(Finding(
                category="privacy",
                severity="low",
                rule="no_privacy_policy_url",
                description="No privacy policy URL detected in the APK. Privacy regulations require apps to link to a privacy policy.",
                evidence="No privacy policy URL found in DEX strings",
            ))
            privacy_score += _NO_PRIVACY_POLICY_PENALTY

    privacy_score = min(privacy_score, 100)
    return findings, privacy_score, trackers


def _detect_tracker_sdks(dx) -> tuple[list[str], list[Finding]]:
    """Scan DEX class names for known tracker SDK package paths."""
    detected: list[str] = []
    findings: list[Finding] = []
    seen: set[str] = set()

    try:
        class_names: list[str] = []
        for cls in dx.get_classes():
            class_names.append(cls.name)
    except Exception:
        return [], []

    class_blob = "\n".join(class_names)

    for tracker_name, prefixes in TRACKER_SDK_DB:
        if tracker_name in seen:
            continue
        for prefix in prefixes:
            if prefix in class_blob:
                detected.append(tracker_name)
                seen.add(tracker_name)
                # Generate a safe rule key from tracker name
                rule_key = "tracker_" + re.sub(r"[^a-z0-9]", "_", tracker_name.lower()).strip("_")
                findings.append(Finding(
                    category="privacy",
                    severity="low",
                    rule=rule_key,
                    description=f"Tracker/analytics SDK detected: {tracker_name}. This SDK collects behavioral and/or device data.",
                    evidence=f"Package path: {prefix}",
                ))
                break

    return detected, findings


def _detect_clipboard_reading(dx) -> list[str]:
    """Find callers of ClipboardManager.getPrimaryClip()."""
    callers = []
    try:
        for cls in dx.get_classes():
            if _CLIPBOARD_CLASS not in cls.name:
                continue
            for method in cls.get_methods():
                if _CLIPBOARD_METHOD not in method.method.name:
                    continue
                for _, caller, _ in method.get_xref_from():
                    callers.append(f"{caller.class_name}->{caller.name}")
                    if len(callers) >= 5:
                        return callers
    except Exception:
        pass
    return callers


def _collect_strings(dx) -> list[str]:
    """Extract string constants from DEX (capped for performance)."""
    strings = []
    try:
        for _, s in dx.get_strings_analysis().items():
            strings.append(str(s.get_orig_value()))
            if len(strings) > 50000:
                break
    except Exception:
        pass
    return strings


def _check_compliance_strings(strings: list[str]) -> tuple[bool, bool, bool]:
    """
    Check for consent, privacy policy, and data retention strings.
    Returns (consent_found, policy_found, retention_found).
    """
    combined = "\n".join(strings)
    consent_found = any(p.search(combined) for p in _CONSENT_PATTERNS)
    policy_found = any(p.search(combined) for p in _PRIVACY_POLICY_PATTERNS)
    retention_found = any(p.search(combined) for p in _DATA_RETENTION_PATTERNS)
    return consent_found, policy_found, retention_found
