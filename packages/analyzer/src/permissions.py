"""
Permission analysis — detects dangerous permission combinations mapped to Google PHA categories.
"""
from .models import Finding

# Each rule: (frozenset of required permissions, category, severity, rule_name, description)
_COMBO_RULES: list[tuple[frozenset, str, str, str, str]] = [
    (
        frozenset(["android.permission.SEND_SMS", "android.permission.INTERNET"]),
        "billing_fraud",
        "high",
        "sms_internet_combo",
        "SMS + INTERNET permissions indicate potential toll fraud or WAP billing fraud.",
    ),
    (
        frozenset(["android.permission.RECEIVE_SMS", "android.permission.INTERNET"]),
        "billing_fraud",
        "high",
        "receive_sms_internet_combo",
        "RECEIVE_SMS + INTERNET permissions indicate potential SMS interception for billing fraud.",
    ),
    (
        frozenset([
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.INTERNET",
        ]),
        "spyware",
        "high",
        "camera_audio_internet_combo",
        "CAMERA + RECORD_AUDIO + INTERNET permissions indicate potential spyware/stalkerware.",
    ),
    (
        frozenset([
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.REQUEST_DELETE_PACKAGES",
        ]),
        "hostile_downloader",
        "high",
        "install_delete_packages_combo",
        "INSTALL_PACKAGES + DELETE_PACKAGES permissions indicate a hostile downloader.",
    ),
    (
        frozenset([
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.INTERNET",
        ]),
        "ransomware",
        "critical",
        "device_admin_internet_combo",
        "BIND_DEVICE_ADMIN + INTERNET permissions indicate ransomware or privilege escalation.",
    ),
    (
        frozenset([
            "android.permission.READ_CONTACTS",
            "android.permission.READ_SMS",
            "android.permission.INTERNET",
        ]),
        "data_collection",
        "high",
        "contacts_sms_internet_combo",
        "READ_CONTACTS + READ_SMS + INTERNET permissions indicate aggressive data collection/spyware.",
    ),
    (
        frozenset([
            "android.permission.READ_CALL_LOG",
            "android.permission.READ_CONTACTS",
            "android.permission.INTERNET",
        ]),
        "spyware",
        "high",
        "call_log_contacts_internet_combo",
        "READ_CALL_LOG + READ_CONTACTS + INTERNET permissions indicate call/contact spyware.",
    ),
    (
        frozenset([
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.INTERNET",
            "android.permission.READ_CONTACTS",
        ]),
        "commercial_spyware",
        "medium",
        "location_contacts_internet_combo",
        "Location + contacts + internet permissions combination indicates commercial spyware.",
    ),
    (
        frozenset([
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.READ_CALL_LOG",
            "android.permission.INTERNET",
        ]),
        "spyware",
        "high",
        "call_interception_combo",
        "PROCESS_OUTGOING_CALLS + READ_CALL_LOG + INTERNET indicates call interception spyware.",
    ),
    (
        frozenset([
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.INTERNET",
            "android.permission.REQUEST_INSTALL_PACKAGES",
        ]),
        "hostile_downloader",
        "high",
        "boot_install_internet_combo",
        "Boot persistence + INSTALL_PACKAGES + INTERNET indicates a persistent hostile downloader.",
    ),
]

# Individually suspicious permissions
_SINGLE_HIGH_RISK: list[tuple[str, str, str, str, str]] = [
    (
        "android.permission.INSTALL_PACKAGES",
        "hostile_downloader",
        "medium",
        "install_packages_permission",
        "INSTALL_PACKAGES permission allows silent installation of arbitrary APKs.",
    ),
    (
        "android.permission.CHANGE_NETWORK_STATE",
        "denial_of_service",
        "low",
        "change_network_state",
        "CHANGE_NETWORK_STATE can be abused for network disruption.",
    ),
    (
        "android.permission.WRITE_SETTINGS",
        "privilege_escalation",
        "low",
        "write_settings_permission",
        "WRITE_SETTINGS can be abused to change critical system settings.",
    ),
    (
        "android.permission.DISABLE_KEYGUARD",
        "ransomware",
        "medium",
        "disable_keyguard_permission",
        "DISABLE_KEYGUARD can be used by ransomware to lock the device.",
    ),
    (
        "android.permission.USE_BIOMETRIC",
        "data_collection",
        "low",
        "biometric_permission",
        "USE_BIOMETRIC access without clear functional need may indicate credential harvesting.",
    ),
]


def analyze_permissions(permissions: list[str]) -> list[Finding]:
    perm_set = set(permissions)
    findings: list[Finding] = []

    for required, category, severity, rule, description in _COMBO_RULES:
        if required.issubset(perm_set):
            evidence = ", ".join(sorted(required))
            findings.append(Finding(
                category=category,
                severity=severity,
                rule=rule,
                description=description,
                evidence=evidence,
            ))

    for perm, category, severity, rule, description in _SINGLE_HIGH_RISK:
        if perm in perm_set:
            findings.append(Finding(
                category=category,
                severity=severity,
                rule=rule,
                description=description,
                evidence=perm,
            ))

    return findings
