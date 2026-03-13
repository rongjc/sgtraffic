"""
Manifest analysis — checks for device admin receivers, accessibility service abuse,
high-risk intent filters, and backup agent misuse.
"""
from .models import Finding


def analyze_manifest(apk) -> list[Finding]:
    """
    Accepts an androguard APK object and returns manifest-level findings.
    """
    findings: list[Finding] = []
    try:
        findings.extend(_check_device_admin(apk))
        findings.extend(_check_accessibility_service(apk))
        findings.extend(_check_high_risk_intent_filters(apk))
        findings.extend(_check_backup_agent(apk))
        findings.extend(_check_dangerous_activities(apk))
    except Exception:
        # Don't let manifest parsing errors abort the whole analysis
        pass
    return findings


def _get_declared_receivers(apk) -> list[str]:
    """Return list of receiver class names declared in the manifest."""
    try:
        return list(apk.get_receivers())
    except Exception:
        return []


def _get_declared_services(apk) -> list[str]:
    try:
        return list(apk.get_services())
    except Exception:
        return []


def _check_device_admin(apk) -> list[Finding]:
    findings = []
    receivers = _get_declared_receivers(apk)
    try:
        # Check for BIND_DEVICE_ADMIN intent filter in receivers
        for receiver in receivers:
            try:
                intent_filters = apk.get_intent_filters("receiver", receiver)
                for action_list in intent_filters.get("action", []):
                    if "android.app.action.DEVICE_ADMIN_ENABLED" in action_list or \
                       "android.app.action.DEVICE_ADMIN_DISABLED" in action_list:
                        findings.append(Finding(
                            category="ransomware",
                            severity="critical",
                            rule="device_admin_receiver",
                            description="App declares a device admin receiver. This is a strong indicator of ransomware or privilege escalation malware.",
                            evidence=f"Receiver: {receiver}",
                        ))
                        break
            except Exception:
                pass

        # Also check via permissions declared
        perms = list(apk.get_declared_permissions()) if hasattr(apk, 'get_declared_permissions') else []
        if "android.permission.BIND_DEVICE_ADMIN" in perms:
            findings.append(Finding(
                category="privilege_escalation",
                severity="high",
                rule="device_admin_permission_declared",
                description="App declares BIND_DEVICE_ADMIN permission, enabling device administration capabilities.",
                evidence="android.permission.BIND_DEVICE_ADMIN",
            ))
    except Exception:
        pass
    return findings


def _check_accessibility_service(apk) -> list[Finding]:
    findings = []
    services = _get_declared_services(apk)
    for service in services:
        try:
            intent_filters = apk.get_intent_filters("service", service)
            for action_list in intent_filters.get("action", []):
                if "android.accessibilityservice.AccessibilityService" in action_list:
                    findings.append(Finding(
                        category="spyware",
                        severity="high",
                        rule="accessibility_service_abuse",
                        description="App registers an accessibility service. This is commonly abused by spyware and banking trojans to read screen content and inject input.",
                        evidence=f"Service: {service}",
                    ))
                    break
        except Exception:
            pass
    return findings


def _check_high_risk_intent_filters(apk) -> list[Finding]:
    findings = []
    HIGH_RISK_ACTIONS = {
        "android.intent.action.BOOT_COMPLETED": (
            "persistence",
            "medium",
            "boot_persistence",
            "App listens for BOOT_COMPLETED to achieve persistence — starts automatically on device boot.",
        ),
        "android.intent.action.PACKAGE_ADDED": (
            "hostile_downloader",
            "medium",
            "package_monitor",
            "App monitors package installations — typical of hostile downloaders tracking installed apps.",
        ),
        "android.intent.action.PACKAGE_REPLACED": (
            "hostile_downloader",
            "low",
            "package_replace_monitor",
            "App monitors package replacements.",
        ),
        "android.provider.Telephony.SMS_RECEIVED": (
            "spyware",
            "high",
            "sms_receiver",
            "App intercepts incoming SMS messages — common in banking trojans and spyware.",
        ),
        "android.provider.Telephony.WAP_PUSH_RECEIVED": (
            "wap_fraud",
            "high",
            "wap_push_receiver",
            "App intercepts WAP push messages — associated with WAP billing fraud.",
        ),
        "android.intent.action.SEND": (
            "spam",
            "low",
            "send_intent_filter",
            "App can intercept SEND intents — potential spam vector.",
        ),
    }

    components = [
        ("receiver", list(apk.get_receivers())),
        ("service", list(apk.get_services())),
        ("activity", list(apk.get_activities())),
    ]
    seen_rules = set()
    for comp_type, comp_list in components:
        for comp in comp_list:
            try:
                intent_filters = apk.get_intent_filters(comp_type, comp)
                for action in intent_filters.get("action", []):
                    if action in HIGH_RISK_ACTIONS and action not in seen_rules:
                        category, severity, rule, description = HIGH_RISK_ACTIONS[action]
                        findings.append(Finding(
                            category=category,
                            severity=severity,
                            rule=rule,
                            description=description,
                            evidence=f"{comp_type}: {comp}, action: {action}",
                        ))
                        seen_rules.add(action)
            except Exception:
                pass
    return findings


def _check_backup_agent(apk) -> list[Finding]:
    findings = []
    try:
        manifest_xml = apk.get_android_manifest_axml().get_xml().decode("utf-8", errors="replace")
        if "android:backupAgent" in manifest_xml and "android:allowBackup=\"true\"" in manifest_xml:
            findings.append(Finding(
                category="data_collection",
                severity="medium",
                rule="backup_agent_misuse",
                description="App declares a custom backup agent with allowBackup=true. Backup agents can be abused to exfiltrate app data.",
                evidence="android:backupAgent with allowBackup=true",
            ))
    except Exception:
        pass
    return findings


def _check_dangerous_activities(apk) -> list[Finding]:
    """Flag activities that could be used for phishing (e.g., overlay attacks)."""
    findings = []
    try:
        activities = list(apk.get_activities())
        for activity in activities:
            try:
                intent_filters = apk.get_intent_filters("activity", activity)
                # Look for activities with MAIN+LAUNCHER that have suspicious names
                actions = intent_filters.get("action", [])
                if "android.intent.action.MAIN" in actions:
                    name_lower = activity.lower()
                    if any(kw in name_lower for kw in ["overlay", "phish", "fake", "spoof"]):
                        findings.append(Finding(
                            category="phishing",
                            severity="high",
                            rule="suspicious_activity_name",
                            description=f"Activity name suggests overlay/phishing attack: {activity}",
                            evidence=f"Activity: {activity}",
                        ))
            except Exception:
                pass
    except Exception:
        pass
    return findings
