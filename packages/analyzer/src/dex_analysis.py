"""
DEX/code analysis — detects obfuscation, command execution, crypto abuse,
dynamic classloading, and native library loading patterns.
"""
from .models import Finding


# Method references that indicate suspicious behavior
# Format: (class_pattern, method_pattern, category, severity, rule, description)
_METHOD_RULES: list[tuple[str, str, str, str, str, str]] = [
    # Reflection / dynamic loading
    (
        "java/lang/reflect",
        "invoke",
        "backdoor",
        "high",
        "reflection_invoke",
        "Use of Java reflection (Method.invoke) can indicate obfuscation or backdoor behavior.",
    ),
    (
        "java/lang/Class",
        "forName",
        "backdoor",
        "high",
        "dynamic_class_loading",
        "Dynamic class loading via Class.forName() is commonly used to hide malicious code.",
    ),
    (
        "dalvik/system/DexClassLoader",
        "",
        "hostile_downloader",
        "critical",
        "dex_classloader",
        "DexClassLoader usage allows loading arbitrary DEX/APK files at runtime — hostile downloader pattern.",
    ),
    (
        "dalvik/system/PathClassLoader",
        "",
        "hostile_downloader",
        "high",
        "path_classloader",
        "PathClassLoader can load classes from arbitrary paths — hostile downloader indicator.",
    ),
    (
        "dalvik/system/InMemoryDexClassLoader",
        "",
        "hostile_downloader",
        "critical",
        "in_memory_dex_classloader",
        "InMemoryDexClassLoader loads DEX bytecode from memory — strong obfuscation/evasion indicator.",
    ),
    # Command execution
    (
        "java/lang/Runtime",
        "exec",
        "backdoor",
        "critical",
        "runtime_exec",
        "Runtime.exec() used for shell command execution — backdoor/rooting behavior.",
    ),
    (
        "java/lang/ProcessBuilder",
        "start",
        "backdoor",
        "high",
        "processbuilder_start",
        "ProcessBuilder.start() used for process execution — command execution pattern.",
    ),
    # Crypto (ransomware)
    (
        "javax/crypto/Cipher",
        "getInstance",
        "ransomware",
        "medium",
        "crypto_cipher",
        "Cipher usage detected — could indicate ransomware encryption routines.",
    ),
    (
        "javax/crypto/SecretKeyFactory",
        "",
        "ransomware",
        "medium",
        "secret_key_factory",
        "SecretKeyFactory usage — key generation for potential ransomware encryption.",
    ),
    (
        "javax/crypto/spec/SecretKeySpec",
        "",
        "ransomware",
        "medium",
        "secret_key_spec",
        "SecretKeySpec usage — symmetric key construction for potential file encryption.",
    ),
    # Native libraries (rootkit/rooting)
    (
        "java/lang/System",
        "loadLibrary",
        "rooting",
        "high",
        "native_library_load",
        "Native library loading via System.loadLibrary() — potential rootkit or privilege escalation.",
    ),
    (
        "java/lang/Runtime",
        "loadLibrary",
        "rooting",
        "high",
        "runtime_loadlibrary",
        "Native library loading via Runtime.loadLibrary() — potential rootkit indicator.",
    ),
    # Data exfiltration helpers
    (
        "android/telephony/SmsManager",
        "sendTextMessage",
        "billing_fraud",
        "high",
        "sms_send_programmatic",
        "Programmatic SMS sending via SmsManager — toll fraud or spam indicator.",
    ),
    (
        "android/content/ContentResolver",
        "query",
        "data_collection",
        "low",
        "content_resolver_query",
        "ContentResolver queries may be used to access contacts, SMS, or call logs.",
    ),
    # Accessibility abuse
    (
        "android/accessibilityservice/AccessibilityService",
        "onAccessibilityEvent",
        "spyware",
        "high",
        "accessibility_event_handler",
        "Accessibility event handling — commonly abused by spyware and banking trojans to monitor screen.",
    ),
    # Device admin
    (
        "android/app/admin/DevicePolicyManager",
        "lockNow",
        "ransomware",
        "critical",
        "device_lock_now",
        "DevicePolicyManager.lockNow() — ransomware device-locking behavior.",
    ),
    (
        "android/app/admin/DevicePolicyManager",
        "wipeData",
        "ransomware",
        "critical",
        "device_wipe_data",
        "DevicePolicyManager.wipeData() — destructive/ransomware behavior.",
    ),
    (
        "android/app/admin/DevicePolicyManager",
        "resetPassword",
        "ransomware",
        "critical",
        "device_reset_password",
        "DevicePolicyManager.resetPassword() — ransomware device lock bypass.",
    ),
]


def analyze_dex(dx) -> list[Finding]:
    """
    Accepts an androguard Analysis object and returns DEX-level findings.
    dx is androguard.core.analysis.analysis.Analysis
    """
    findings: list[Finding] = []
    seen_rules: set[str] = set()

    try:
        for class_pattern, method_pattern, category, severity, rule, description in _METHOD_RULES:
            if rule in seen_rules:
                continue
            try:
                matches = _find_method_calls(dx, class_pattern, method_pattern)
                if matches:
                    evidence = "; ".join(matches[:3])  # Show first 3 callers
                    findings.append(Finding(
                        category=category,
                        severity=severity,
                        rule=rule,
                        description=description,
                        evidence=evidence,
                    ))
                    seen_rules.add(rule)
            except Exception:
                pass
    except Exception:
        pass

    return findings


def _find_method_calls(dx, class_pattern: str, method_pattern: str) -> list[str]:
    """
    Search for usages of methods matching class_pattern/method_pattern.
    Returns a list of caller strings (for evidence).
    """
    callers = []
    try:
        for cls in dx.get_classes():
            class_name = cls.name.strip("L;").replace("/", "/")
            if class_pattern and class_pattern not in cls.name:
                continue
            for method in cls.get_methods():
                m = method.method
                if method_pattern and method_pattern not in m.name:
                    continue
                # This class+method matched — find who calls it
                for _, caller, _ in method.get_xref_from():
                    caller_name = f"{caller.class_name}->{caller.name}"
                    callers.append(caller_name)
                    if len(callers) >= 5:
                        return callers
    except Exception:
        pass
    return callers
